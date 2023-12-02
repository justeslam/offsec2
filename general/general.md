Conceptualize a learning model based on increasing uncertainty.

#################

The recommended way to SSH into Module Exercise VMs:
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@191.168.50.52
```

##################

The `sudo updatedb` command in Linux is used to update the database used by the `locate` command. This command is part of the `mlocate` package, which provides a way to quickly locate files on a system by building a database of file names and their paths.

```bash
sudo updatedb
locate pen199.ovpn
```

##################

Connect to a VPN.

```bash
sudo openvpn pen199.ovpn
```

Must leave this command prompt open.

#################

193.168.{third octet of TUN0 network interface}.{specific octet associated with the machine}

################

"Whether you think you can or think you can’t—you’re right." - Henry Ford

###############

If you don't have the permissions to execute a file, check if you have permissions to copy (read) the file somewhere that you DO have permission to execute.

###############

The Feynman Technique:

0. Learn a Module
1. Explain it to a beginner
2. Identify gaps
3. Return to study

##############

The SQ2R method has learners follow a pattern of study activities: survey, question, read, recite, review. 

#############

OWASP Penetrating Testing Execution Standard:

- Pre-engagement Interactions
- Intelligence Gathering
- Threat Modeling
- Vulnerability Analysis
- Exploitation
- Post Exploitation
- Reporting

##############

Taking Notes / Report Writing:

- Understand the scope
- Write down the ROE, Rules of Engagement
- Make sure that it is precise & repeatable, assume little to no knowledge
- Must be easily understandable by others
- Needs to be portable, preferably in the cloud
- Every command must be included
- Remove any notes that are not helpful
- Sublime, CherryTree & Obsidian are recommended

For a web application vulnerability, include:

- Application Name
- URL
- Request Type
- Issue Detail
- Proof of Concept Payload

A good screenshot has the following characteristics:

- Is legible
- Contains some visual indication that it applies to the client
- Contains the material that is being described
- Supports the description of the material
- Properly frames the material being described

On the other hand, a bad screenshot is one that:

- Is illegible
- Is generic rather than client-specific
- Contains obfuscated or irrelevant information
- Is improperly framed

###################