# LimaCharlie — Cloud EDR

LimaCharlie cloud EDR extends visibility to endpoints without running a local agent server. Complements Velociraptor in the lab — LimaCharlie handles cloud-native EDR detection scenarios that are increasingly common in enterprise environments.

## Detection rules written
D&R (Detection and Response) rules covering:
- LSASS access
- Suspicious PowerShell execution
- Unsigned binary in temp directory
- Outbound connection to known-bad IP

## Screenshots
<!-- Add after build -->
![LimaCharlie endpoints enrolled](screenshots/limacharlie-endpoints.png)
![D&R rule firing](screenshots/limacharlie-detection.png)
