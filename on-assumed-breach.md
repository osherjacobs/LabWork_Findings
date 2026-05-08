# On Assumed Breach

A tendency I've noticed in discussions around post-compromise research: the finding is often declared invalid unless the full attack path from low-privileged initial access all the way to total compromise is shown in a single, contiguous demonstration. As if somehow that means there are no realistic paths to admin other than being handed credentials through authorized means.

Assumed breach is a methodology, not an oversight. It deliberately begins after elevated access has been achieved — because that is exactly the phase real intrusions enter once prevention has failed. The relevant questions are operational: What telemetry is actually generated? How fast can it be correlated? How much time does the defender realistically have?

These are not academic questions. They determine whether a breach is contained or becomes catastrophic.

There is a school of thought that treats post-compromise research as incomplete or irrelevant unless it also demonstrates the entire kill chain from low privileges. That position is understandable but flawed. It conflates initial access problems with post-compromise reality and ignores the many legitimate ways elevated access is routinely obtained in real environments.

Furthermore, the irony is clear: detailing a full, novel execution chain from initial entry to Domain Admin on a public forum would be labeled irresponsible disclosure by the very people making the aforementioned objection of incompleteness / irrelevance. Yet starting the demonstration at the post-elevation phase is labeled incomplete. It is a rhetorical trap that serves only to keep the detection gap unaddressed.

The reflex to invalidate these findings because "the full path wasn't shown" is a major contributing factor to why breaches continue to succeed at scale. It allows organizations to avoid confronting what actually happens once elevated context is reached — which occurs routinely through lateral movement, delegation, token theft, and misconfigurations.

Prevention matters. Post-compromise visibility, detection speed, and response matter more.

If your threat model ends at "the attacker shouldn't have admin," it is not modelling threats — it is validating assumptions. And it leaves you with no meaningful answer to what happens when he does.

An organization that dismisses assumed breach research has not built a mature security program. It has built an untested hypothesis that prevention will never fail.

Assumed breach exists to stress-test the layers that matter when prevention fails. That has always been the point.

---

*Part of the [AD Lab Research](https://github.com/osherjacobs/AD-Lab-Research) series.*
