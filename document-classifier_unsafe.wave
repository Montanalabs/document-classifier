#! VULNERABLE document-classifier — feeds the untrusted document straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant file

let doc = fetch<web>
privileged { file(doc) }  # tainted -> tool: REJECTED
