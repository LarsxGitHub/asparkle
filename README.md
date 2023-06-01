# ASPA observatory

Utility to calculate the ASPA deployment status at a given date.
Fully written with ❤️ in :crab:. Built atop the amazing [BGPKit framework](https://bgpkit.com) and the [RPKIViews](rpkiviews.org) repository. 

### Upstream Inference.

The ASPA Verification RFC specifies that "The upstream verification algorithm ... is applied when a route is received from a customer or lateral peer, or is received by an RS from an RS-client, or is received by an RS-client from an RS." Our observatory looks at BGP paths collected from hundreds of "randomly" chosen ASes, i.e., the data we receive contains path that may contain upstreams and downstreams. hence, we first extract each path's upstream section via the following set of inference heuristics:

1. If we encounter one of the well-known provider-free network (also known as Tier 1 ASNs), we assume that every hop between the Origin and the Tier 1 belongs to the upstream. If we find that the ASN after the Tier 1 is a non-transparent route server, we infer the route server to be part of the upstream (as CAS are supposed to include non-transparent route servers within their aspa records.)
2. If we encounter a non-transparent route server, we assume that every hop between the origin and the route server is part of the upstream.
3. if we encounter an hop with an valid aspa attestation, we assume that all hops between the origin and the CAS's provider are part of the upstream. Notably, if we find multiple valid ASPA's, we choose the one furthest away from the origin. 
4. If we receive data from a route collector peer that is a route server, we assume that all its paths consist of only upstreams.
5. BGP Roles. 
