#! Document classifier — an untrusted document can only ever become one of a fixed set of
#! filing commands, never a tool argument. An injected instruction cannot be represented in
#! the closed type, so it is rejected at the trust boundary (and re-clamped at run time by
#! extract). Each command carries a payload from its own closed set, so even that can't be smuggled.
#! @requires file — the document-filing tool
#! @effect io — carries out the filing command
#! @taint bridge — extract<Decision> turns the tainted document into a trusted command
grant file

type Category = Invoice | Contract | Report | Resume
type Dept = Finance | Legal | People
type Decision = Classify(Category) | Route(Dept) | Reject

let doc = fetch<web>  # UNTRUSTED document — tainted
quarantined { let d = extract<Decision>(doc) }  # only a fixed Decision (payload too) crosses
privileged { file(d) }  # act on the trusted command only
