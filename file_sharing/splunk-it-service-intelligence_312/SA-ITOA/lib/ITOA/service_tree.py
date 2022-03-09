import uuid


def generate_subgraphs_json(data, service_id_filter=[], logger=None):
    """
    Handles a request to create a service tree from the given data.

    @type data: list
    @param data: the raw service data

    @type service_id_filter: list
    @param service_id_filter: the list of filtered service ids

    @type logger: object
    @param logger: the logger to use

    @rtype: list
    @return: the list of subgraphs in the tree
    """
    tree = ServiceTree(logger=logger)

    vertices = tree.parse_services_to_vertices(data)
    filtered_vertices = tree.filter_vertices(vertices, service_id_filter)
    subgraphs = tree.create_subgraphs(filtered_vertices)
    return tree.subgraphs_to_json(subgraphs)


class ServiceTree(object):
    """
    Class to interact with service trees
    """

    def __init__(self, logger=None):
        """
        @type logger: object
        @param logger: the logger to use
        """
        self.logger = logger

    def parse_services_to_vertices(self, services_data):
        """
        Parse the raw services data, returning a lookup dict from service key
        to a vertex representing the service in the tree.

        @type services_data: dict
        @param services_data: the raw services data

        @rtype: dict
        @return: dict from service key to its vertex in the tree
        """
        if not services_data:
            return {}

        vertices = {}

        for service_data in services_data:
            service_id = service_data.get('_key', None)
            if not service_id:
                continue

            vertex = vertices.setdefault(service_id, ServiceVertex(service_id))
            vertex.title = service_data.get('title', '')

            # Parse the service's dependent services (parents)
            parent_ids = []
            for parent in service_data.get('services_depends_on', []):
                parent_id = parent.get('serviceid', None)
                if not parent_id:
                    continue
                parent_ids.append(parent_id)

            # Set the vertex's parents
            parents = {vertices.setdefault(parent_id, ServiceVertex(parent_id))
                       for parent_id in parent_ids}
            vertex.parents.update(parents)

            # Add this vertex to its parents as a child
            for parent in parents:
                parent.children.add(vertex)

            vertices[service_id] = vertex

        return vertices

    def filter_vertices(self, vertices, vertex_ids):
        """
        Filters the given list of vertices by another list of vertex ids. Only
        vertices that are connected to a vertex in vertex_ids in a meaningful
        way are included in the output list.

        @type vertices: dict
        @param vertices: the lookup dict from vertex id to service vertex

        @type vertex_ids: list
        @param vertices: the list of vertex ids to filter for

        @rtype: dict
        @return: dict from service key to its vertex in the tree
        """
        if not vertex_ids:
            return vertices

        # Maintain separate structures for keeping track of which vertices we've visited
        # from a particular direction (i.e. either through children or through parents)
        children = set()
        parents = set()

        # Traverse the vertices so that only the impacted services are visited
        for vertex_id in vertex_ids:
            vertex = vertices.get(vertex_id, None)
            if not vertex:
                continue

            vertex.traverse_children(children)
            vertex.traverse_parents(parents)

        visited = set()
        visited.update(children)
        visited.update(parents)

        # Update the vertices edge data with only the visited vertices
        filtered = {}
        for v in visited:
            filtered[v.id] = v
            v.children.intersection_update(visited)
            v.parents.intersection_update(visited)

        return filtered

    def create_subgraphs(self, vertices):
        """
        Groups connected vertices into a subgraph object.

        @type vertices: dict
        @param vertices: the lookup dict from vertex id to service vertex

        @rtype: list
        @return: list of subgraphs
        """
        subgraphs = []
        visited = set()

        for vertex in vertices.values():
            if vertex in visited:
                continue

            subgraph = Subgraph()
            subgraph.populate_from(vertex, visited)
            subgraphs.append(subgraph)

        return subgraphs

    def subgraphs_to_json(self, subgraphs):
        """
        Returns a JSON-friendly object representing the list of subgraphs.

        @type subgraphs: list
        @param subgraphs: the list of subgraph objects

        @rtype: list of dict
        @return: list of subgraphs that can be converted to JSON
        """
        graphs = []
        total = 0

        for subgraph in subgraphs:
            # putting vertices with highest degrees first seems to create
            # better looking graphs
            sorted_edges = sorted(subgraph.edges,
                                  key=lambda e: (e[1].degree, e[0].degree,
                                                 e[1].title, e[0].title),
                                  reverse=True)
            edges = [{
                'source': e[1].id,
                'target': e[0].id
            } for e in sorted_edges]

            vertices = [{
                'id': v.id,
                'title': v.title
            } for v in sorted(subgraph.vertices, key=lambda x: x.title)]

            graphs.append({
                'id': subgraph.id,
                'edges': edges,
                'vertices': vertices
            })

            total += len(vertices)

        return {
            'graphs': graphs,
            'totalCount': total
        }


class Subgraph(object):
    """
    A subgraph representing a connected graph of vertices in the service tree.
    """

    def __init__(self):
        self.id = str(uuid.uuid4())
        self.vertices = set()
        self.edges = set()

    def populate_from(self, start_vertex, visited):
        """
        Populates this subgraph's vertices and edges data by traversing from
        the given start vertex.

        NOTE: The visited set param is modified during this call.

        @type start_vertex: ServiceVertex
        @param start_vertex: the vertex to start traversing from

        @type visited: set
        @param visited: set containing the already visited vertices
        """
        stack = [start_vertex]

        while stack:
            v = stack.pop()

            for child in v.children:
                if child in visited:
                    continue

                self.edges.add((v, child))
                stack.append(child)

            for parent in v.parents:
                if parent in visited:
                    continue

                self.edges.add((parent, v))
                stack.append(parent)

            self.vertices.add(v)
            visited.add(v)


class ServiceVertex(object):
    """
    A vertex in the service tree, containing parent and children edge data.
    """

    def __init__(self, id):
        self.id = id
        self.title = None
        self.children = set()
        self.parents = set()

    def _traverse(self, edge_attr, visited):
        """
        Traverses the connected graph through the children of this vertex.

        @type edge_attr: str
        @param edge_attr: the edge attribute name to use for the traversal

        @type visited: set
        @param visited: set containing the already visited vertices
        """
        stack = [self]

        while stack:
            v = stack.pop()
            stack.extend([n for n in getattr(v, edge_attr)
                          if n not in visited])
            visited.add(v)

    def traverse_children(self, visited):
        """
        Traverses the connected graph through the children of this vertex.

        @type visited: set
        @param visited: set containing the already visited vertices
        """
        self._traverse('children', visited)

    def traverse_parents(self, visited):
        """
        Traverses the connected graph through the parents of this vertex.

        @type visited: set
        @param visited: set containing the already visited vertices
        """
        self._traverse('parents', visited)

    @property
    def degree(self):
        """
        Returns the degree of the vertex.

        @rtype: int
        @return: the number of edges connected to the vertex
        """
        return len(self.children) + len(self.parents)

    def __repr__(self):
        return u'[ServiceVertex] %s' % self.id
