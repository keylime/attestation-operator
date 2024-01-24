# Push Model using proxy

This is a proposal for using a proxy implementation to achieve the "push model" for the agent.
The term "push model" refers to a change in the design of the keylime agent:
Currently the keylime agent provides a server implementation from which verifiers "pull" quotes for verification.
Moving towards a push model would reverse the role: the agent would conntinously "push" quotes to verifiers for verification.

## Problem Statement

With the current model the keylime agent needs to run a server and listen on incoming network connections.
This poses problems for some deployments.
In most cases the common denominators for these deployments are the following reasons:

- The agents are deployed behind a NAT, and the verifier cannot directly reach the agent
- There are other network configurations and circumstances which cause problems for the verifier to communicate with the agent
- Security requirements prohibit the deployments of a server application that is reachable over the network; considering that not even SSH servers are welcomed any longer in modern deployments, this is a problem that needs to be taken seriously

Therefore the deployment is either impossible or prohibited.

## Solution

The move towards a push model for the agent solves all the reasons mentioned in the problem statement.

## Status Quo

Before we move on to look at the proposal on how to achieve the push model, let us take a step and discover the status quo of communication between the keylime components.
In the current model we have the following communication diagram between the components:

1. keylime agents register with the keylime registrar over plain HTTP on startup, communicating essential attributes like IP and port as well as a TLS server certificate for further communication with the agent
2. the keylime tenant or the Kubernetes controller / attestation operator (simply called tenant going forward) detect and identify agents by querying the registrar over mTLS, retrieving information on how to contact the agents
3. for making use of the secure payload delivery feature, the tenant communicates part of the key material with the agent directly, it knows how through the registrar information, as well as the encrypted payload itself
4. the tenant then adds the agent to a verifier of its choosing, communicating agent IP and port, as well as other essential information from the registrar and key material for the secure payload delivery to the verifier by POSTing it to the verifier over an mTLS connection
5. the verifier will then make regular requests to the agent over an mTLS connection to query the identity/integrity quote of the TPM, it will also communicate the missing key material for the secure payload feature after a successful quote
6. last but not least, the tenant can optionally send a challenge to the agent to verify that the key for the secure payload delivery was successfully derived at the agent


```asciiflow
                                            +-------------------+
                         http [1]           |                   |
+------------+------------------------------> keylime-registrar <----+
|            |                              |                   |    |
|   +--------+--------+                     +-------------------+    |
|   |                 | https/mTLS [5]                               |
| +-> keylime-agent 1 <------------------------+                     |
| | |                 |                        |                     |
| | +-----------------+                     +--+-----------------+   |
| |                         [4] https/mTLS  |                    |   |
| |                                     +---> keylime-verifier 1 |   |
| |                                     |   |                    |   |
| | +-----------------+                 |   +--------------------+   |
| | |                 | https/mTLS [5]  |                            |
+-+-+ keylime-agent 2 <-----------------+-----+                      |
  | |                 |                 |     |                      |
  | +--^--------------+                 |   +-+------------------+   |
  |    |                                |   |                    |   |
  |    |                                +---> keylime-verifier 1 |   |
  |    |                                |   |                    |   |
  |    |                                |   +--------------------+   |
  |    |                                |                            |
  |    |                 +--------------+-+                          |
  |    |                 |                |                          |
  +----+-----------------+ keylime-tenant |                          |
   [6] [3] https/mTLS    | k8s controller +--------------------------+
                         |                |   https/mTLS [2]
                         +----------------+
```

## Problems to move to a push model

As a summary the main problem is that there are two keylime components which currently communicate with the agent directly: the tenant and verifier.

While the replacement of the verifier communication could potentially be modeled through placing some additional information in the registrar and let the agent poll on that until the verifier information becomes available for itself from which point it could "push" regular quotes to the verifier, another problem is that the tenant component is a CLI with which the agent would need to interact.

Again, a way out of this might be that the tenant puts the information into the registrar for the agent to fetch.
However, besides from this being a workaround, this also changes the requirements for communicating with the registrar as this information should not be retrieved over an unauthenticated and insecure connection.

Last but not least, as the agent is now pushing quotes to the verifier, it also changes the requirements for communicating with the verifier: this now also requires a mTLS connection which poses the problem that these certificates would need to be provisioned beforehand.
However, this sort of defeats the purpose of keylime in many deployment scenarios where it is being used to establish trust with the machine that it is onboarding, so that it could itself provision these type of certificates for other components (that is after all what the secure payload feature is good for).
As a way out of this, one could potentially switch to using the EK certificate or a derivative of it, like in the proposal below.

As a conclusion I believe it is impossible to facilitate the move towards a push model without a fundamental architectural change.
Therefore the solution proposed below is *not* requiring an architecture change at all.
Instead it is trying to simply work around the communication requirements that are currently posing these problems.

## Proxy Proposal

To allow the current architecture to work we need a proxy component that can be colocated with the other keylime core components like the keylime verifier.
The role of the proxy is twofold and provides the following servers:

1. An implementation of a gRPC server that the keylime agents connect to. The gRPC interface can easily facilitate verifier pulls for quotes through a stream interface.
2. An implementation of the existing agent HTTP REST API. The tenant as well as the verifier will communicate to the agents through the existing REST APIs as before.

The proxy endpoint for (1) can be a "public" endpoint and requires a mTLS connection.
This essentially solves the requirements from the problem statement.
This endpoint should also be served from behind a load balancer.
It allows to spread the connections from all agents evenly to all proxy instances.
Key for this connection is that the client certificate that the agent presents represents the TPM.
The EK certificate could be used here (or potentially a derivative of it), and it means that the proxy will also automatically have to do EK certificate verification.
However, this ensures that the proxy can trust that the agent, which is connecting to it, has physical access to the TPM.
It also continues to ensure, like in the current deployment model, that there are no other certificates which need to be deployed to the machines beforehand.

The proxy endpoint for (2) does not necessarily need to be public.
On the contrary the only requirement for it is that verifiers (and tenants) need to be able to connect to the individual proxy instances directly.
Therefore it is important that this south bound API does *not* sit behind a load balancer.
The targeted idea behind a proxy deployment would see the proxies be deployed colocated with the verifiers that it needs to support.
Proxies each need to generate a server certificate on startup which can be ephemeral which will be used for storage in the registrar as the "mtls_certificate".

The communication diagram changes to the following.
It is important to know that except for (1), the workflow stays exactly the same:

1. Keylime agents connect over gRPC with a keylime proxy instance. A Load Balancer is placed before this endpoint to evenly distribute connections between agents and their proxy instance. It is important to note that the connection must be made between an agent and a keylime proxy instance, so a layer 7 load balancer (even one that understands gRPC) can not be used
   1. Agents present their EK certificate (or potentially a derivative) to the proxy, and the proxy must perform EK certificate validation. This authenticates the agent and its TPM.
   2. Proxies keep state of all their connected agents, and drop an agent if it disconnects.
   3. Agents perform a single bidirectional streaming RPC call. This simulates the agent being called as before.
   4. On this call it needs to send all the information that was sent to the registrar before to the proxy.
   5. Agents need to monitor and detect gRPC connection state changes, and if one occurs, they need to reperform (1.3) as they could connect to a different proxy instance.
2. On the proxy side it needs to make the call to the registrar on (1.4) and store within the registrar the following data:
   1. the EK cert as it comes from the agent
   2. the AIK as it comes from the agent
   3. the MTLS certificate as generated on proxy startup
   4. the IP and port of the proxy instance, and where it is serving the agent REST API on; this is where the agent can be reached from the tenant and verifier perspective
3. the keylime tenant detect and identify agents by querying the registrar over mTLS, retrieving information on how to contact the agents
4. for making use of the secure payload delivery feature, the tenant wants to communicate part of the key material with the agent as well as the encrypted payload itself
   1. The registrar information now contains the information about the proxy instance to which the tenant needs to connect to in order to reach the right agent.
   2. It is transparent to the tenant as this just looks and feels like a normal keylime agent.
   3. It sends part of the key material and the payload to the proxy instance.
   4. The proxy instance in turn looks up if it has the agent in the request connected to itself.
   5. If it does not have the agent in its connection state, it fails the request with an HTTP 404. This is eventual consistent as in cases of flux the agents will reregister and update the tenant with the new correct proxy information.
   6. If it exists, it uses the bidirectional streaming gRPC API to send a message to the agent which represents the "Send U" API.
5. the tenant then adds the agent to a verifier of its choosing, communicating agent IP and port (--> in reality the proxy IP and port), as well as other essential information from the registrar and key material for the secure payload delivery to the verifier by POSTing it to the verifier over an mTLS connection
6. the verifier will then make regular requests to the agent (--> proxy) over an mTLS connection to query the identity/integrity quote of the TPM, it will also communicate the missing key material for the secure payload feature after a successful quote
   1. again, the connection is established to the south bound API of a specific proxy instance
   2. The proxy instance looks up if it has the agent in the request connected to itself.
   3. If it does not have the agent in its connection state, it fails the request with an HTTP 404. This is eventual consistent as in cases of flux the agents will reregister and update the tenant with the new correct proxy information.
   4. If it exists, it uses the bidirectional streaming gRPC API to send a request and receive a reply for the identity/integrity quote.
7. last but not least, the tenant can optionally send a challenge to the agent (--> proxy) to verify that the key for the secure payload delivery was successfully derived at the agent
   1. again, the connection is established to the south bound API of a specific proxy instance
   2. The proxy instance looks up if it has the agent in the request connected to itself.
   3. If it does not have the agent in its connection state, it fails the request with an HTTP 404. This is eventual consistent as in cases of flux the agents will reregister and update the tenant with the new correct proxy information.
   4. If it exists, it uses the bidirectional streaming gRPC API to send the challenge request and receive its reply.


```asciiflow
                                                                                                 +-------------------+
                                                                          [2] http               |                   |
+------------------+                                 +------------+------------------------------> keylime-registrar <----+
|                  |                                 |            |                              |                   |    |
| keylime-agent 1  +-+                               |   +--------+--------+                     +-------------------+    |
|                  | |                               |   |                 | https/mTLS [6]                               |
+------------------+ |                               | +-> keylime-proxy 1 <------------------------+                     |
                     |                               | | |                 |                        |                     |
+------------------+ |           +----------------+  | | +--------^--------+                     +--+-----------------+   |
|                  | |  [1] gRPC |                |  | | [1] gRPC |              [5] https/mTLS  |                    |   |
| keylime-agent 2  | +-----------> Load Balancer--+--+-+----------+                          +---> keylime-verifier 1 |   |
|                  | |           |                |  | |          |                          |   |                    |   |
+------------------+ |           +----------------+  | | +--------v--------+                 |   +--------------------+   |
                     |                               | | |                 | https/mTLS [6]  |                            |
+------------------+ |                               +-+-+ keylime-proxy 2 <-----------------+-----+                      |
|                  | |                                 | |                 |                 |     |                      |
| keylime-agent 3  +-+                                 | +--^--------------+                 |   +-+------------------+   |
|                  |                                   |    |                                |   |                    |   |
+------------------+                                   |    |                                +---> keylime-verifier 1 |   |
                                                       |    |                                |   |                    |   |
                                                       |    |                                |   +--------------------+   |
                                                       |    |                                |                            |
                                                       |    |                 +--------------+-+                          |
                                                       |    |                 |                |                          |
                                                       +----+-----------------+ keylime-tenant |                          |
                                                        [7] [4] https/mTLS    | k8s controller +--------------------------+
                                                                              |                |   [3] https/mTLS
                                                                              +----------------+
```

### Pros

- no changes to existing keylime architecture required
- solves the problem statement without any fundamental changes to core keylime components and workflow
- can be scaled easily by simply starting multiple proxies and placing a standard load balancer in front
- resource footprint for the proxy should be minimal (particular if developed in Rust)

### Cons

- requires an implementation of an alternate mode within the agent (this is unavoidable though in any case)
- requires a network connection for all agents between agent and proxies at all time (this is how gRPC works, and is not too much of an issue as long as it is taken into consideration for scaling)
- losing a proxy (which could be a simple restart of the application) requires onboarding of all previously connected agents to this server (not really a problem with the attestation operator as it takes care of this operation already in its early alpha state)
