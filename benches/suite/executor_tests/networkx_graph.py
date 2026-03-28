import networkx as nx
G = nx.karate_club_graph()
pagerank = nx.pagerank(G)
communities = list(nx.community.greedy_modularity_communities(G))
top_node = max(pagerank, key=pagerank.get)
shortest = nx.average_shortest_path_length(G)
print(f"nodes={G.number_of_nodes()} edges={G.number_of_edges()} communities={len(communities)} top_pr={top_node} avg_path={shortest:.2f}")
