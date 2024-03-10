<!-- Heading -->
<h3 align="center">Process Hallowing Shellcode Injection with UAC Bypass</h3>
<!-- About section -->

---

Attackers can exploit the technique of inserting harmful code into dormant processes that have been emptied of their original content, as a means to bypass defenses aimed at monitoring processes. This tactic, known as process hollowing, involves executing unauthorized code within the memory space of another running process.

Typically, process hollowing is executed by starting a new process in a paused state, then clearing or "hollowing" out its memory, which is subsequently filled with malicious code. This is achieved through the use of native Windows API functions such as CreateProcess, which can initiate a process with its primary thread suspended. Following this, the process's memory can be cleared using functions like ZwUnmapViewOfSection or NtUnmapViewOfSection, and then modified to incorporate the harmful code. The steps include reallocating memory with VirtualAllocEx, writing the new code with WriteProcessMemory, adjusting the thread context with SetThreadContext, and finally resuming the thread with ResumeThread.

This method is somewhat akin to manipulating Thread Local Storage, with the key difference being that it generates a new process instead of hijacking an existing one. While this approach does not typically grant the attacker higher privileges—since the new process inherits the security context of the process that created it—it can still escape detection by security tools because the malicious activity appears to occur within a legitimate process.

---

The implementation of the [KernelCallbackTable](https://captmeelo.com/redteam/maldev/2022/04/21/kernelcallbacktable-injection.html) njection is incomplete.
