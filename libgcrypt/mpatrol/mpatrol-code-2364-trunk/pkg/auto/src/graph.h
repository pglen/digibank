#ifndef MP_GRAPH_H
#define MP_GRAPH_H


/*
 * mpatrol
 * A library for controlling and tracing dynamic memory allocations.
 * Copyright (C) 1997-2008 Graeme S. Roy <graemeroy@users.sourceforge.net>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/*
 * Directed graphs.  Such graphs have an adjacency list representation as
 * they are likely to be sparse, and may be built as cyclic or acyclic.
 * Only the linkage between graph nodes is dealt with by this module -
 * dynamically allocating memory for nodes is done elsewhere.
 */


/*
 * $Id: graph.h 2293 2008-12-16 13:21:04Z graemeroy $
 */


#include "config.h"
#include "list.h"


/* A graph node simply contains linkage information and is intended to be
 * used as a member for any datatypes that need to belong to a graph.
 */

typedef struct graphnode
{
    listhead parents;  /* list of parent nodes */
    listhead children; /* list of child nodes */
}
graphnode;


/* A graph edge may belong to the parent node's list of children and the
 * child node's list of parents.
 */

typedef struct graphedge
{
    listnode pnode;           /* parent list node in child */
    listnode cnode;           /* child list node in parent */
    struct graphnode *parent; /* parent node */
    struct graphnode *child;  /* child node */
}
graphedge;


/* A graph head contains a sentinel start node and a sentinel end node
 * in order to make graph manipulation and traversal simpler.
 */

typedef struct graphhead
{
    struct graphnode start; /* first node of graph */
    struct graphnode end;   /* last node of graph */
    size_t nodes;           /* number of nodes in graph */
    size_t edges;           /* number of edges in graph */
}
graphhead;


#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */


MP_EXPORT void __mp_newgraph(graphhead *);
MP_EXPORT void __mp_addnode(graphhead *, graphnode *);
MP_EXPORT void __mp_removenode(graphhead *, graphnode *);
MP_EXPORT void __mp_addedge(graphhead *, graphedge *, graphnode *, graphnode *);
MP_EXPORT void __mp_removeedge(graphhead *, graphedge *);
MP_EXPORT graphedge *__mp_findedge(graphhead *, graphnode *, graphnode *);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* MP_GRAPH_H */
