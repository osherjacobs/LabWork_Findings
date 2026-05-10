# On Assumed Breach and atherosclerosis

<img width="822" height="587" alt="lsassinitelligent" src="https://github.com/user-attachments/assets/9e9fc5c9-5d85-442c-a376-a655c9907438" />


A tendency I've noticed in discussions around post-compromise research: the finding is often declared invalid unless the full attack path from low-privileged initial access all the way to total compromise is shown in a single, contiguous demonstration. As if that somehow proves there are no realistic paths to admin other than being handed credentials through authorized means.

Assumed breach is a methodology, not an oversight. It deliberately begins after elevated access has been achieved — because that is exactly the phase real intrusions enter once prevention has failed. The relevant questions are operational: What telemetry is actually generated? How fast can it be correlated? How much time does the defender realistically have?

These are not academic questions. They determine whether a breach is contained or becomes catastrophic.

There is a school of thought that treats post-compromise research as incomplete or irrelevant unless it also demonstrates the entire kill chain from low privileges. That objection is both factually wrong and logically inconsistent.

It is factually wrong because elevated access is commonplace in real intrusions. It is routinely achieved through lateral movement, token theft, delegation abuse, and misconfigured service accounts — not just by being handed credentials. The starting condition is not invented. It is observed.

It is logically inconsistent because assumed breach does not claim that prevention always fails. It models what happens when it fails — which it does, reliably, against even moderately skilled attackers. Research that stress-tests post-compromise detection is not invalidated by the existence of perimeter controls. It is made more necessary by their limitations.

Those who have actually performed lateral movement in real environments don't ask "but how did you get admin?" They ask what the detection pipeline actually saw — because they know the difference between theory and reality.

Dismissing post-compromise research because the full kill chain wasn't demonstrated is like rejecting a medical study on heart attack treatment because the researchers didn't study how the patient developed atherosclerosis in the first place. The argument sounds technical. It isn't. It is a demand for infinite regression dressed up as rigor.

Furthermore, the irony is delicious: publishing a full, novel execution chain from initial access to Domain Admin on a public forum would be instantly labeled irresponsible disclosure by the very same people calling post-elevation research "incomplete." It is a perfect rhetorical trap — one that results in the real detection gap going unaddressed.

The reflex to invalidate these findings because "the full path wasn't shown" is a major contributing factor to why breaches continue to succeed at scale. It allows organizations to avoid confronting what actually happens once elevated context is reached — which occurs routinely through lateral movement, delegation, token theft, and misconfigurations.

Prevention matters. Post-compromise visibility, detection speed, and response matter more.

If your threat model ends at "the attacker shouldn't have admin," it is not modelling threats — it is validating assumptions. And it leaves you with no meaningful answer to what happens when he does.

An organization that dismisses assumed breach research has not built a mature security program. It has built an untested hypothesis that prevention will never fail.

Assumed breach exists to stress-test the layers that matter when prevention fails. That has always been the point.

---

*Part of the [AD Lab Research](https://github.com/osherjacobs/AD-Lab-Research) series.*
A tendency I've noticed in discussions around post-compromise research: the finding is often declared invalid unless the full attack path from low-privileged initial access all the way to total compromise is shown in a single, contiguous demonstration. As if that somehow proves there are no realistic paths to admin other than being handed credentials through authorized means.

Assumed breach is a methodology, not an oversight. It deliberately begins after elevated access has been achieved — because that is exactly the phase real intrusions enter once prevention has failed. The relevant questions are operational: What telemetry is actually generated? How fast can it be correlated? How much time does the defender realistically have?

These are not academic questions. They determine whether a breach is contained or becomes catastrophic.

There is a school of thought that treats post-compromise research as incomplete or irrelevant unless it also demonstrates the entire kill chain from low privileges. That objection is both factually wrong and logically inconsistent.

It is factually wrong because elevated access is commonplace in real intrusions. It is routinely achieved through lateral movement, token theft, delegation abuse, and misconfigured service accounts — not just by being handed credentials. The starting condition is not invented. It is observed.

It is logically inconsistent because assumed breach does not claim that prevention always fails. It models what happens when it fails — which it does, reliably, against determined attackers. Research that stress-tests post-compromise detection is not invalidated by the existence of perimeter controls. It is made more necessary by their limitations.

Those fluent in privilege escalation and lateral movement techniques don't ask 'but how did you get admin?' They ask 'what did the pipeline see?'.

Dismissing post-compromise research because the full kill chain wasn't demonstrated is like rejecting a medical study on heart attack treatment because the researchers didn't study how the patient developed atherosclerosis in the first place. The argument sounds technical. It isn't. It is a most curious demand for infinite regression dressed up as rigor.

Furthermore, the irony is clear: publishing a full, novel execution chain from initial access to Domain Admin on a public forum would be labeled irresponsible disclosure by the very same people calling post-elevation research "incomplete." It is a rhetorical trap resulting in the real detection gap going unaddressed.

The reflex to invalidate these findings because "the full path wasn't shown" is a major contributing factor to why breaches continue to succeed at scale. It allows organizations to avoid confronting what actually happens once elevated context is reached — which occurs routinely through lateral movement, delegation, token theft, and misconfigurations.

Prevention matters. Post-compromise visibility, detection speed, and response matter more.

If your threat model ends at "the attacker shouldn't have admin," it is not modelling threats — it is validating assumptions. And it leaves you with no meaningful answer to what happens when he does.

An organization that dismisses assumed breach research has not built a mature security program. It has built an untested hypothesis that prevention will never fail.

Assumed breach exists to stress-test the layers that matter when prevention fails. That has always been the point.

---

*Part of the [AD Lab Research](https://github.com/osherjacobs/AD-Lab-Research) series.*
