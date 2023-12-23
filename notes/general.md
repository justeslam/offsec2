## Generic Notes

### Learning and Problem-Solving Strategies

1. **Feynman Technique for Learning**:
   - Learn a Module.
   - Explain it to a beginner.
   - Identify gaps in understanding.
   - Return to study to fill those gaps.

2. **SQ2R Method for Study**:
   - Survey, Question, Read, Recite, Review.

3. **Inspirational Quote by Henry Ford**:
   - "Whether you think you can or think you can’t—you’re right."

---

### Technical Procedures and Commands

1. **Accessing Module Exercise VMs via SSH**:
   ```bash
   ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@191.168.50.52
   ```

2. **Updating and Locating Files in Linux**:
   - Update the database with `sudo updatedb`.
   - Locate specific files using `locate`.
     Example:
     ```bash
     sudo updatedb
     locate pen199.ovpn
     ```

3. **Connecting to a VPN**:
   - Use `sudo openvpn` to connect.
   - Keep the command prompt open.
     Example:
     ```bash
     sudo openvpn pen199.ovpn
     ```

4. **Addressing File Execution Permission Issues**:
   - If lacking execution permissions, copy the file to a location where execution is permitted.

---

### Networking and IP Addressing

- Use the format `193.168.{third octet of TUN0 network interface}.{specific octet associated with the machine}` for specific network addressing.

---

### Penetration Testing Methodologies

1. **OWASP Penetrating Testing Execution Standard**:
   - Pre-engagement Interactions.
   - Intelligence Gathering.
   - Threat Modeling.
   - Vulnerability Analysis.
   - Exploitation.
   - Post Exploitation.
   - Reporting.

---

### Effective Note-taking and Report Writing

1. **General Guidelines**:
   - Understand the scope.
   - Document the Rules of Engagement.
   - Ensure clarity and precision.
   - Make notes easily understandable and repeatable.
   - Use cloud storage for portability.
   - Include every relevant command.
   - Discard unhelpful notes.
   - Recommended tools: Sublime, CherryTree, Obsidian.

2. **Documenting Web Application Vulnerabilities**:
   - Application Name, URL, Request Type, Issue Detail, Proof of Concept Payload.

3. **Characteristics of Good and Bad Screenshots**:
   - Good: Legible, relevant to the client, supports description, properly frames the material.
   - Bad: Illegible, generic, contains irrelevant information, poorly framed.

---

#### Processes

To filter processes to find the processes you'd like:
```bash
ps aux | grep process_name
```
Aux argument will provide all processes, and piping to grep filters.

---

#### Adding Resositories

Sources are stored in /etc/apt/sources.list. Let's say that a package isn't found, so you can't install new binaries or packages, you're likely missing the source location in which the binary or package is held. Modify the provided file to include the source you need.

#### sed

Stream editor.

```bash
sed s/mysql/MySQL/g /etc/snort/snort.conf > snort2.conf
```
Find all of the occurences of 'mysql' (s/mysql), and replace them with 'MySQL globally' (/MySQL/g) in the file '/etc/snort/snort.conf', and sent the output to 'snort2.conf'

---

#### strings

Pull the strings out of any file.

#### Changing MAC Address

```bash
sudo ifconfig eth0 down
sudo ifconfig eth0 hw ether 00:00:00:11:11:11
sudo ifconfig eth0 up
```

#### Obsidian 

Obsidian stores information in a Vault, which is a folder on our system. We can create both markdown files and folders within the Vault. Obsidian's features include a live preview of markdown text, in-line image placement, code blocks, and a multitude of add-ons such as a community-built CSS extension.

An Obsidian vault can be relocated to another computer and opened from the Welcome menu. Markdown files can simply be dropped into the Vault folders, which will automatically be recognized by Obsidian.

The use of markdown means that we can provide syntax and formatting that is easily copied to most report generation tools, and a PDF can be generated straight from Obsidian itself.

Installing:

```bash
wget https://github.com/obsidianmd/obsidian-releases/releases/download/v0.14.2/Obsidian-0.14.2.AppImage
chmod +x Obsidian-0.14.2.AppImage
./Obsidian-0.`14.2.AppImage
```

Some additional cool tools are located in 'https://github.com/nil0x42/awesome-hacker-note-taking'.