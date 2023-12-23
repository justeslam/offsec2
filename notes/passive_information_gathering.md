# Information Gathering


Good to Know

- To begin information gathering, we typically perform reconnaissance to retrieve details about the target organization's infrastructure, assets, and personnel.
- Active information gathering reveals a bigger footprint, so it is often preferred to avoid exposure by gathering information passively.
- Information gathering = enumeration
- Could buy a domain, build a quick website to establish trust
  - embed client-side attack exploit code in the site's web pages
- Can search vulnerabilities using local DocsGPT for further exploitation options

Process

### Whois

Whois1 is a TCP service, tool, and type of database that can provide information about a domain name, such as the name server and registrar. This information is often public, since registrars charge a fee for private registration.

To look up domain information:
```bash
whois domain.com -h 192.168.x.x
```

Do reverse lookup IP address:
```bash
ip_address -h server
```

Google Search Hacking

- Only display from a certain website: `site:megacorpone.com`
- Only display a certain file type: `filetype:txt`
- Search for particular extensions: `ext:php`
- Don't display something: `site:gunnar.ai -filetype:html`
- Only display if in title: `intitle: "index of"`
Resource: Google Hacking Database, Dorksearch.com

#### Netcraft

- Used to gather more information about domains, such as discovering which technologies are running in a given website and finding which other hosts share the same IP netblock
- We can view a "site report" that provides additional information and history about the server by clicking on the file icon next to each site URL
Resource: [Netcraft](https://searchdns.netcraft.com)

#### GitHub

- GitHub is a great place to discover more information about a company's technology and infrastructure. There may be information that wasn't intended to be released on the platform.

Resource: Gitrob, Gitleaks

#### Shodan

- A search engine that crawls devices connected to the internet, including the servers that run websites, and devices like routers and IoT devices.
- We can review the ports, services, and technologies used by the server on this page. Shodan will also reveal if there are any published vulnerabilities for any of the identified services or technologies running on the same host.
Resource: [Shodan](https://www.shodan.io)

Security Headers

- Analyze HTTP response headers and provide basic analysis of the target site's security posture
Alternative - SSL Labs
Resource: [Security Headers](https://securityheaders.com/), [SSL Labs](https://www.ssllabs.com/ssltest/)
```
