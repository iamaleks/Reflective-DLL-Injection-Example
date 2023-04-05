# Reflective DLL Injection Example

Example implementation of Reflective DLL Injection.

Related to blog post located at [https://posts.thinkbox.dev/posts/2023/01/10/malware-techniques-reflective-dll-injection](https://posts.thinkbox.dev/posts/2023/01/10/malware-techniques-reflective-dll-injection)

## Execution Instructions

1. Copy Reflective DLL Payload to `C:\`.

The `ReflectiveDLL.dll` file should be located under `C:\ReflectiveDLL.dll`.

2. Ensure notepad.exe is running

The `ReflectiveDLLInjector.exe` is made to inject into a running instance of notepad.exe.

3. Execute `ReflectiveDLLInjector.exe`

Run `ReflectiveDLLInjector.exe` with administrator permissions.
