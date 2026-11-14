# Schemas

**These files are normative.** The `predicateType` in an attestation is a URI because
in-toto's format requires one; it is an *identifier*, nothing in this tool fetches it, and
nothing requires it to resolve. What defines the format is the file in this directory.

That is not a stylistic preference. A customer holding ten-year CRA evidence cannot depend
on a domain outliving a company, and a verifier that fetched a schema over the network to
check a 2036-vintage document would have built the failure mode into the evidence. So the
schema travels with the Apache-2.0 source, versioned by directory, and a copy of this
repository at any commit is a complete definition of every document it could produce.

| file | `predicateType` | what it is |
|---|---|---|
| [`v1/attestation.schema.json`](v1/attestation.schema.json) | `https://buildclamp.dev/attestation/v1` | what was built, under which policy, and which tier actually held each capability |
| [`v1/erratum.schema.json`](v1/erratum.schema.json) | `https://buildclamp.dev/erratum/v1` | a signed correction saying that statements matching some criteria overstate a tier |

## A prerequisite that is recorded rather than discovered

**The domain in those URIs is not registered.** Until it is, a third party could take it and
serve a schema disagreeing with the committed one — which matters less than it would for a
tool that fetched it, and still matters. Registering it is a precondition to relying
on those URIs.

## Versioning

A new directory, never an edit. A schema is the thing a ten-year-old document is read
against, so `v1/` is frozen the moment anything signs against it; a change that would make
an existing document invalid is `v2/` with a new URI. Adding an **optional** field is the
only in-place change these files will ever take, and `additionalProperties` is left open on
each object for exactly that — a verifier written today must read a document written later
rather than rejecting it, because the alternative is a customer whose evidence stops
verifying when the vendor ships.
