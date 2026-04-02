WordPress - Discovery & Enumeration

WordPress, launched in 2003, is an open-source Content Management System (CMS) that can be used for multiple purposes. It’s often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.

At the time of writing, WordPress accounts for around 32.5% of all sites on the internet and is the most popular CMS by market share. Here are some interesting  facts about WordPress.

• WordPress offers over 50,000 plugins and over 4,100 GPL-licensed themes
• 317 separate versions of WordPress have been released since its initial launch
• Roughly 661 new WordPress websites are built every day
• WordPress blogs are written in over 120 languages
• A study showed that roughly 8% of WordPress hacks happen due to weak passwords, while 60% were due to an outdated WordPress version
• According to WPScan, out of nearly 4,000 known vulnerabilities, 54% are from plugins, 31.5% are from WordPress core, and 14.5% are from WordPress themes.
• Some major brands that use WordPress include The New York Times, eBay, Sony, Forbes, Disney, Facebook, Mercedes-Benz, and many more

As we can see from these statistics, WordPress is extremely prevalent on the internet and presents a vast attack surface. We are guaranteed to come across WordPress during many of our External Penetration Test assessments, and we must understand how it works, how to enumerate it, and the various ways it can be attacked.

Let us imagine that during an external penetration test, we come across a company that hosts its main website based on WordPress. Like many other applications, WordPress has individual files that allow us to identify that application. Also, the files, folder structure, file names, and functionality of each PHP script can be used to discover even the installed version of WordPress. In this web application, by default, metadata is added by default in the HTML source code of the web page, which sometimes even already contains the version. Therefore, let us see what possibilities we have to find out more detailed information about WordPress.

Comprehensive Enumeration Checklist
Phase 1: Initial Discovery

• WordPress Confirmation - robots.txt, directory structure, meta tags

• Version Detection - Core version identification

• Directory Listing - Check for exposed directories

• XML-RPC Status - Test availability and functionality

Phase 2: Component Analysis

• Active Theme - Identification and version detection

• Plugin Discovery - Enumerate installed plugins

• Plugin Versions - Specific version identification

• User Enumeration - Valid username discovery

Phase 3: Vulnerability Mapping

• CVE Research - Map versions to known vulnerabilities

• Configuration Issues - Default credentials, exposed files

• Custom Code Review - Theme/plugin custom functionality

Phase 4: Attack Surface Assessment

• Entry Points - Login forms, comment sections, contact forms

• File Upload - Media upload functionality

• Administrative Access - wp-admin accessibility

• API Endpoints - REST API and XML-RPC availability

Common Vulnerability Patterns

Outdated Core Installation

# Impact: Multiple CVEs affecting core functionality
### Risk: High - Core vulnerabilities often lead to RCE

#### Vulnerable Plugins

# Most Common: 
# - Contact Form 7 (various versions)
# - wpDiscuz (RCE vulnerabilities)
# - mail-masta (LFI vulnerabilities)
# - File Manager plugins (arbitrary file access)

# Detection Strategy:
# 1. Enumerate all plugins
# 2. Identify exact versions
# 3. Cross-reference with vulnerability databases

Default/Weak Credentials

# Common credentials to test:
admin:admin
admin:password
admin:123456
wordpress:wordpress

# Test against wp-login.php and wp-admin access

Directory Listing Enabled

# Check critical directories:
/wp-content/plugins/			# Plugin source code exposure
/wp-content/uploads/			# Uploaded file enumeration  
/wp-content/themes/			# Theme file access

WordPress Architecture & Components

Core Directory Structure

/wp-admin/				# Administrative backend
/wp-content/			# Themes, plugins, uploads
  /plugins/					# Third-party plugins
  /themes/					# WordPress themes
  /uploads/				# User-uploaded content
/wp-includes/			# Core WordPress files
wp-config.php		# Configuration file
wp-login.php			# Login page
xmlrpc.php				# XML-RPC interface
readme.html			# Version information
robots.txt					# Search engine directives

User Role Hierarchy

Administrator			→ Full administrative access + code execution potential
Editor							→ Publish/manage all posts + plugin access
Author						→ Publish/manage own posts
Contributor				→ Write/manage posts (cannot publish)
Subscriber				→ Browse posts + edit profile

Discovery/Footprinting
A quick way to identify a WordPress site is by browsing to the /robots.txt file. A typical robots.txt on a WordPress installation may look like:

Method 1: robots.txt Analysis


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Check robots.txt for WordPress indicators
curl -s http://target.com/robots.txt

# Typical WordPress robots.txt:
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 

Here the presence of the /wp-admin and /wp-content directories would be a dead giveaway that we are dealing with WordPress. Typically attempting to browse to the wp-admin directory will redirect us to the wp-login.php page. This is the login portal to the WordPress instance's back-end.

http://blog.inlanefreight.local/wp-login.php

WordPress stores its plugins in the wp-content/plugins directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the wp-content/themes directory. These files should be carefully enumerated as they may lead to RCE.

There are five types of users on a standard WordPress installation.

1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

Getting access to an administrator is usually sufficient to obtain code execution on the server. Editors and authors might have access to certain vulnerable plugins, which normal users don’t.

Enumeration

Method 2: HTML Meta Generator Tag

Another quick way to identify a WordPress site is by looking at the page source. Viewing the page with cURL and grepping for WordPress can help us confirm that WordPress is in use and footprint the version number, which we should note down for later. We can enumerate WordPress using a variety of manual and automated tactics.

$ curl -s http://blog.inlanefreight.local | grep -i WordPress

Method 3: Directory Detection

# Test for common WordPress directories
curl -I http://blog.inlanefreight.local/wp-admin/
curl -I http://blog.inlanefreight.local/wp-content/
curl -I http://blog.inlanefreight.local/wp-login.php

# Look for redirects to wp-login.php (indicates WordPress)

Method 4: File Signature Detection

# Check for WordPress-specific files
curl -I http://blog.inlanefreight.local/readme.html
curl -I http://blog.inlanefreight.local/wp-config.php
curl -I http://blog.inlanefreight.local/xmlrpc.php

Theme Identification & Analysis

Discovering Active Theme

Browsing the site and perusing the page source will give us hints to the theme in use, plugins installed, and even usernames if author names are published with posts. We should spend some time manually browsing the site and looking through the page source for each page, grepping for the wp-content directory, themes and plugin, and begin building a list of interesting data points.

Looking at the page source, we can see that the Business Gravity theme is in use. We can go further and attempt to fingerprint the theme version number and look for any known vulnerabilities that affect it.

$ curl -s http://blog.inlanefreight.local/ | grep themes

Theme Version Detection

# Check theme directory for version files
curl -s http://target.com/wp-content/themes/business-gravity/readme.txt
curl -s http://target.com/wp-content/themes/business-gravity/style.css | grep Version

Plugin Discovery & Enumeration

Source Code Analysis

$ curl -s http://blog.inlanefreight.local/ | grep plugins

From the output above, we know that the Contact Form 7 and mail-masta plugins are installed. The next step would be enumerating the versions.

Browsing to http://blog.inlanefreight.local/wp-content/plugins/mail-masta/ shows us that directory listing is enabled and that a readme.txt file is present. These files are very often helpful in fingerprinting version numbers. From the readme, it appears that version 1.0.0 of the plugin is installed, which suffers from a Local File Inclusion vulnerability that was published in August of 2021.

Direct Plugin Testing

# Test for common plugins
curl -I http://target.com/wp-content/plugins/wp-super-cache/
curl -I http://target.com/wp-content/plugins/yoast-seo/
curl -I http://target.com/wp-content/plugins/contact-form-7/

Let's dig around a bit more. Checking the page source of another page, we can see that the wpDiscuz plugin is installed, and it appears to be version 7.0.4

$ curl -s http://blog.inlanefreight.local/?p=1 | grep plugins

Plugin Version Detection

# Check plugin readme files for version information
curl -s http://target.com/wp-content/plugins/mail-masta/readme.txt

# Look for version indicators in plugin files
curl -s http://target.com/wp-content/plugins/plugin-name/ | grep -i version

A quick search for this plugin version shows this unauthenticated remote code execution vulnerability from June of 2021. We'll note this down and move on. It is important at this stage to not jump ahead of ourselves and start exploiting the first possible flaw we see, as there are many other potential vulnerabilities and misconfigurations possible in WordPress that we don't want to miss.

Directory Listing Exploitation

Checking for Exposed Directories

# Test common WordPress directories for listing
curl -s http://target.com/wp-content/plugins/
curl -s http://target.com/wp-content/themes/
curl -s http://target.com/wp-content/uploads/

# Look for directory indexes that reveal file structure

XML-RPC Discovery

# Test XML-RPC availability
curl -X POST http://target.com/xmlrpc.php

# XML-RPC can be used for:
# - Brute force attacks
# - DDoS amplification
# - Information disclosure

Enumerating Users
We can do some manual enumeration of users as well. As mentioned earlier, the default WordPress login page can be found at /wp-login.php.

A valid username and an invalid password results in the following message:

http://blog.inlanefreight.local/wp-login.php

However, an invalid username returns that the user was not found.

This makes WordPress vulnerable to username enumeration, which can be used to obtain a list of potential usernames.

Username Enumeration via Login Form

# Test valid username with invalid password
curl -X POST http://target.com/wp-login.php -d "log=admin&pwd=wrongpassword" -v

# Response: "The password for username admin is incorrect."

# Test invalid username
curl -X POST http://target.com/wp-login.php -d "log=nonexistent&pwd=password" -v

# Response: "The username nonexistent is not registered on this site."

Author ID Enumeration

# Enumerate users via author parameter
for i in {1..10}; do
  curl -s "http://target.com/?author=$i" | grep -i "author"
done

# Look for redirects or author page content

REST API User Enumeration

# WordPress REST API user endpoint
curl -s http://target.com/wp-json/wp/v2/users | jq .

# Extract usernames from JSON response
curl -s http://target.com/wp-json/wp/v2/users | jq '.[].slug'


Let's recap. At this stage, we have gathered the following data points:

• The site appears to be running WordPress core version 5.8
• The installed theme is Business Gravity
• The following plugins are in use: Contact Form 7, mail-masta, wpDiscuz
• The wpDiscuz version appears to be 7.0.4, which suffers from an unauthenticated remote code execution vulnerability
• The mail-masta version seems to be 1.0.0, which suffers from a Local File Inclusion vulnerability
• The WordPress site is vulnerable to user enumeration, and the user admin is confirmed to be a valid user

Let's take things a step further and validate/add to some of our data points with some automated enumeration scans of the WordPress site. Once we complete this, we should have enough information in hand to begin planning and mounting our attacks.

Automated Enumeration with WPScan

Installation & Setup

WPScan is an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a blog are outdated or vulnerable. It’s installed by default on Parrot OS but can also be installed manually with gem.

# Install WPScan
sudo gem install wpscan

# Get WPVulnDB API token (75 requests/day free)
# Register at https://wpvulndb.com/

WPScan is also able to pull in vulnerability information from external sources. We can obtain an API token from WPVulnDB, which is used by WPScan to scan for PoC and reports. The free plan allows up to 25 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to wpscan using the --api-token parameter.

Basic Enumeration Scan

Typing wpscan -h will bring up the help menu.

$ wpscan -h

The --enumerate flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users. By default, WPScan enumerates vulnerable plugins, themes, users, media, and backups. However, specific arguments can be supplied to restrict enumeration to specific components. For example, all plugins can be enumerated using the arguments --enumerate ap. Let’s invoke a normal enumeration scan against a WordPress website with the --enumerate flag and pass it an API token from WPVulnDB with the --api-token flag.

$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

# Comprehensive WordPress enumeration
wpscan --url http://target.com --enumerate --api-token YOUR_API_TOKEN

# Specific enumeration options:
# ap = All plugins
# at = All themes  
# u  = Users
# m  = Media files
# cb = Config backups

WPScan uses various passive and active methods to determine versions and vulnerabilities, as shown in the report above. The default number of threads used is 5. However, this value can be changed using the -t flag.

This scan helped us confirm some of the things we uncovered from manual enumeration (WordPress core version 5.8 and directory listing enabled), showed us that the theme that we identified was not exactly correct (Transport Gravity is in use which is a child theme of Business Gravity), uncovered another username (john), and showed that automated enumeration on its own is often not enough (missed the wpDiscuz and Contact Form 7 plugins). WPScan provides information about known vulnerabilities. The report output also contains URLs to PoCs, which would allow us to exploit these vulnerabilities.

Advanced WPScan Usage

Plugin-Focused Enumeration

# Enumerate all plugins (including inactive)
wpscan --url http://target.com --enumerate ap --api-token YOUR_API_TOKEN

# Aggressive plugin detection
wpscan --url http://target.com --enumerate ap --plugins-detection aggressive

User Enumeration & Brute Force

# Enumerate users only
wpscan --url http://target.com --enumerate u

# Brute force discovered users
wpscan --url http://target.com --usernames admin,john --passwords passwords.txt

Custom Wordlists

# Use custom plugin/theme wordlists
wpscan --url http://target.com --enumerate ap --plugins-list custom_plugins.txt

WPScan Output Analysis

Vulnerability Assessment

# Example WPScan output interpretation:
[!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
    Fixed in: 5.8.1
    References:
     - https://wpvulndb.com/vulnerabilities/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
     - CVE-2021-39200

[!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
    Fixed in: N/A
    References:
     - https://wpvulndb.com/vulnerabilities/f0f1a868-4462-4def-b4e7-1f1c5c534247

Version Detection Strategies

Core WordPress Version

# Multiple methods for version detection:

# 1. Meta generator tag
curl -s http://target.com | grep generator

# 2. RSS feed generator
curl -s http://target.com/?feed=rss2 | grep generator

# 3. readme.html file
curl -s http://target.com/readme.html | grep Version

# 4. Version parameter in scripts/styles
curl -s http://target.com | grep -oP 'ver=\K[0-9.]+'

Plugin/Theme Versioning

# Version detection methods:

# 1. readme.txt files
curl -s http://target.com/wp-content/plugins/PLUGIN/readme.txt | grep "Stable tag"

# 2. CSS/JS version parameters  
curl -s http://target.com | grep -oP 'plugin-name.*?ver=\K[0-9.]+'

# 3. Plugin headers in PHP files
curl -s http://target.com/wp-content/plugins/PLUGIN/plugin-file.php | grep "Version:"

Target: blog.inlanefreight.local

Step 1: Initial Fingerprinting

# Confirm WordPress installation
curl -s http://blog.inlanefreight.local/robots.txt
# Output shows /wp-admin/ and /wp-content/ directories

# Check version
curl -s http://blog.inlanefreight.local | grep generator
# Output: <meta name="generator" content="WordPress 5.8" />

Step 2: Theme & Plugin Discovery

# Identify theme
curl -s http://blog.inlanefreight.local/ | grep themes
# Output: /wp-content/themes/business-gravity/

# Find plugins
curl -s http://blog.inlanefreight.local/ | grep plugins
# Output: contact-form-7, mail-masta, wpDiscuz plugins detected

Step 3: User Enumeration

# Test login error messages
curl -X POST http://blog.inlanefreight.local/wp-login.php -d "log=admin&pwd=test"
# Output: "The password for username admin is incorrect."
# Confirms 'admin' is a valid user

Step 4: Automated Validation

# WPScan confirmation
wpscan --url http://blog.inlanefreight.local --enumerate --api-token TOKEN
# Confirms findings and identifies additional vulnerabilities



Moving On
From the data we gathered manually and using WPScan, we now know the following:

• The site is running WordPress core version 5.8, which does suffer from some vulnerabilities that do not seem interesting at this point
• The installed theme is Transport Gravity
• The following plugins are in use: Contact Form 7, mail-masta, wpDiscuz
• The wpDiscuz version is 7.0.4, which suffers from an unauthenticated remote code execution vulnerability
• The mail-masta version is 1.0.0, which suffers from a Local File Inclusion vulnerability as well as SQL injection
• The WordPress site is vulnerable to user enumeration, and the users admin and jo hn are confirmed to be valid users
• Directory listing is enabled throughout the site, which may lead to sensitive data exposure
• XML-RPC is enabled, which can be leveraged to perform a password brute-forcing attack against the login page using WPScan, Metasploit, etc.

With this information noted down, let's move on to the fun stuff: attacking WordPress!


HTB Academy Lab Solutions


10.129.42.195

vim /etc/hosts

10.129.42.195	 blog.inlanefreight.local

Enumerate the host and find a flag.txt flag in an accessible directory.

# Test directory listing on common paths
curl -s http://blog.inlanefreight.local/wp-content/uploads/
curl -s http://blog.inlanefreight.local/wp-content/plugins/
curl -s http://blog.inlanefreight.local/wp-content/themes/

# Look for exposed files in plugin directories
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
# Check for flag.txt in exposed directories

curl -s http://blog.inlanefreight.local/wp-content/uploads/

0ptions_ind3xeS_ftw!


Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words).

curl -s http://blog.inlanefreight.local/ | grep plugins

curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/

# Analyze different pages for plugin references
curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
curl -s http://blog.inlanefreight.local/category/news/ | grep plugins

# Check page source on multiple URLs:
# - Homepage
# - Individual posts (?p=1, ?p=2)
# - Category pages
# - Archive pages

# Look for plugin CSS/JS files not found in initial scan

WP Sitemap Page

 
Find the version number of this plugin. (i.e., 4.5.2)

# Check plugin directory for version files
curl -s http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/readme.txt
curl -s http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/style.css | grep Version
curl -s http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/ | grep -i version

# Look for version in plugin CSS/JS URLs
curl -s http://blog.inlanefreight.local/?p=1 | grep -oP 'contact-form-7.*?ver=\K[0-9.]+'

5.4.2

contact-form-7
