use crate::config::types::{IsolateError, Result};
use std::collections::HashSet;

use super::contract::{EnforcementMode, KernelDomain, KernelRequirement, REQUIRED_STAGE_ORDER};

pub trait KernelStage: Send + Sync {
    fn name(&self) -> &'static str;
    fn domain(&self) -> KernelDomain;
    fn requirements(&self) -> &'static [KernelRequirement];
    fn apply(&self, mode: EnforcementMode) -> Result<()>;
    fn verify(&self, mode: EnforcementMode) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct KernelRunReport {
    pub mode: EnforcementMode,
    pub applied_stages: Vec<&'static str>,
    pub verified_stages: Vec<&'static str>,
}

pub struct KernelPipeline<'a> {
    mode: EnforcementMode,
    stages: Vec<&'a dyn KernelStage>,
}

impl<'a> KernelPipeline<'a> {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            stages: Vec::new(),
        }
    }

    pub fn push_stage(&mut self, stage: &'a dyn KernelStage) -> &mut Self {
        self.stages.push(stage);
        self
    }

    pub fn stages(&self) -> &[&'a dyn KernelStage] {
        &self.stages
    }

    pub fn validate_order(&self) -> Result<()> {
        let mut previous_rank = 0usize;
        let mut seen_stage_names = HashSet::new();
        for (idx, stage) in self.stages.iter().enumerate() {
            if !seen_stage_names.insert(stage.name()) {
                return Err(IsolateError::Config(format!(
                    "Kernel v2 stage plan contains duplicate stage name '{}'",
                    stage.name()
                )));
            }

            let rank = domain_rank(stage.domain()).ok_or_else(|| {
                IsolateError::Config(format!(
                    "Kernel v2 stage '{}' has domain {:?} outside required ordering",
                    stage.name(),
                    stage.domain()
                ))
            })?;

            if idx > 0 && rank < previous_rank {
                return Err(IsolateError::Config(format!(
                    "Kernel v2 stage ordering violation: '{}' ({:?}) appears before required predecessor",
                    stage.name(),
                    stage.domain()
                )));
            }
            previous_rank = rank;
        }
        Ok(())
    }

    pub fn validate_required_domains(&self) -> Result<()> {
        let seen_domains: HashSet<KernelDomain> =
            self.stages.iter().map(|stage| stage.domain()).collect();
        let missing: Vec<String> = REQUIRED_STAGE_ORDER
            .iter()
            .filter(|domain| !seen_domains.contains(domain))
            .map(|domain| format!("{:?}", domain))
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(IsolateError::Config(format!(
                "Kernel v2 stage plan is missing required domains: {}",
                missing.join(", ")
            )))
        }
    }

    pub fn run(&self) -> Result<KernelRunReport> {
        self.validate_order()?;
        self.validate_required_domains()?;

        let mut applied = Vec::with_capacity(self.stages.len());
        for stage in &self.stages {
            stage.apply(self.mode)?;
            applied.push(stage.name());
        }

        let mut verified = Vec::with_capacity(self.stages.len());
        for stage in &self.stages {
            stage.verify(self.mode)?;
            verified.push(stage.name());
        }

        Ok(KernelRunReport {
            mode: self.mode,
            applied_stages: applied,
            verified_stages: verified,
        })
    }
}

fn domain_rank(domain: KernelDomain) -> Option<usize> {
    REQUIRED_STAGE_ORDER
        .iter()
        .position(|candidate| *candidate == domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct DummyStage {
        name: &'static str,
        domain: KernelDomain,
    }

    impl KernelStage for DummyStage {
        fn name(&self) -> &'static str {
            self.name
        }

        fn domain(&self) -> KernelDomain {
            self.domain
        }

        fn requirements(&self) -> &'static [KernelRequirement] {
            &[]
        }

        fn apply(&self, _mode: EnforcementMode) -> Result<()> {
            Ok(())
        }

        fn verify(&self, _mode: EnforcementMode) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn rejects_out_of_order_stages() {
        let signal = DummyStage {
            name: "signal",
            domain: KernelDomain::Signal,
        };
        let mount = DummyStage {
            name: "mount",
            domain: KernelDomain::Mount,
        };

        let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
        pipeline.push_stage(&signal).push_stage(&mount);

        assert!(pipeline.validate_order().is_err());
    }

    #[test]
    fn rejects_duplicate_stage_names() {
        let namespace = DummyStage {
            name: "namespace",
            domain: KernelDomain::Namespace,
        };
        let mount = DummyStage {
            name: "namespace",
            domain: KernelDomain::Mount,
        };

        let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
        pipeline.push_stage(&namespace).push_stage(&mount);

        assert!(pipeline.validate_order().is_err());
    }

    #[test]
    fn rejects_missing_required_domains() {
        let namespace = DummyStage {
            name: "namespace",
            domain: KernelDomain::Namespace,
        };
        let mount = DummyStage {
            name: "mount",
            domain: KernelDomain::Mount,
        };

        let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
        pipeline.push_stage(&namespace).push_stage(&mount);

        assert!(pipeline.validate_required_domains().is_err());
        assert!(pipeline.run().is_err());
    }

    #[test]
    fn accepts_complete_order_and_runs() {
        let namespace = DummyStage {
            name: "namespace",
            domain: KernelDomain::Namespace,
        };
        let mount = DummyStage {
            name: "mount",
            domain: KernelDomain::Mount,
        };
        let cgroup = DummyStage {
            name: "cgroup",
            domain: KernelDomain::Cgroup,
        };
        let credentials = DummyStage {
            name: "credentials",
            domain: KernelDomain::Credentials,
        };
        let capabilities = DummyStage {
            name: "capabilities",
            domain: KernelDomain::Capabilities,
        };
        let signal = DummyStage {
            name: "signal",
            domain: KernelDomain::Signal,
        };
        let cleanup = DummyStage {
            name: "cleanup",
            domain: KernelDomain::Cleanup,
        };
        let evidence = DummyStage {
            name: "evidence",
            domain: KernelDomain::Evidence,
        };
        let seccomp = DummyStage {
            name: "seccomp",
            domain: KernelDomain::Seccomp,
        };

        let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
        pipeline
            .push_stage(&namespace)
            .push_stage(&mount)
            .push_stage(&cgroup)
            .push_stage(&credentials)
            .push_stage(&capabilities)
            .push_stage(&signal)
            .push_stage(&cleanup)
            .push_stage(&evidence)
            .push_stage(&seccomp);

        let report = pipeline.run().expect("pipeline should run");
        assert_eq!(
            report.applied_stages,
            vec![
                "namespace",
                "mount",
                "cgroup",
                "credentials",
                "capabilities",
                "signal",
                "cleanup",
                "evidence",
                "seccomp"
            ]
        );
        assert_eq!(report.verified_stages, report.applied_stages);
    }
}
