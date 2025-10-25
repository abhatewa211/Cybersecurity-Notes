Juice Shop is written in Node.js, Express and Angular. It was the first application written entirely in **JavaScript** listed in the [OWASP VWA Directory](https://owasp.org/www-project-vulnerable-web-applications-directory).

## Prerequisites

### **• Visit the official OWASP Juice Shop website:**

[https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image.png)

```bash
ssh root@192.168.1.31
```

## SYSTEM UPDATE & SETUP

```bash
apt update
```

```bash
apt upgrade
```

### install curl

```jsx
apt install curl
```

### set hostname

```jsx
vim /etc/hostname
```

any name = “webpentest”

### (optional)

```jsx
reboot
```

---

---

## CONFIGURE NODE.JS for OWASP

[https://github.com/juice-shop/juice-shop#nodejs-version-compatibility](https://github.com/juice-shop/juice-shop#nodejs-version-compatibility)

[GitHub - juice-shop/juice-shop: OWASP Juice Shop: Probably the most modern and sophisticated insecure web application](https://github.com/juice-shop/juice-shop#nodejs-version-compatibility)

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%201.png)

**here we use either 22.x or 20.x nodejs for OWASP linux bcoz its supported and trusted**  

---

---

## INSTALLATION node.js

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%202.png)

### add repo

```jsx
curl -fsSl [https://deb.nodesource.com/setup_22.x](https://deb.nodesource.com/setup_22.x) | sudo bash -
```

### if don’t have sudo then run without sudo

```jsx
curl -fsSl [https://deb.nodesource.com/setup_22.x](https://deb.nodesource.com/setup_22.x) | bash -
```

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%203.png)

### install nodejs from repo

```jsx
apt-get install -y nodejs
```

## configure nodejs

### help

```jsx
node - -help
```

version

```jsx
node -v  or node - -version
```

<aside>
✅

**NPM is the package manager of NODE like pip is package manager of python**

</aside>

```jsx
npm - -help
npm -v 
npm - -version
```

## install the juiceshop tar file

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%204.png)

copy the link(node22 or 20) that you selcted earlier and wget 

```jsx
wget [https://github.com/juice-shop/juice-shop/releases/download/v18.0.0/juice-shop-18.0.0_node22_linux_x64.tgz](https://github.com/juice-shop/juice-shop/releases/download/v18.0.0/juice-shop-18.0.0_node22_linux_x64.tgz)
```

### check the file hash (verify checksum)

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%205.png)

### untar the file downloaded

```jsx
tar -xvf filename
```

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%206.png)

we can place the file anywhere except root 

## Start JUICE SHOP

### cd /opt/juice-shop_18.0.0

```jsx
npm start
```

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%207.png)

if everything goes well juice shop will start on port 3000

### browse juice shop from the server

192.168.1.31:3000

![image.png](OWASP%20JUICE%20SHOP%20installation%20225dcbc1249580c6816aff1a9d8b2ac3/image%208.png)

---

---

---

---

---

### • GitHub repository for Juice Shop:

OWASP Juice Shop GitHub

• Packaged distributions for Juice Shop:

 Packaged Distributions

• Node.js download and installation instructions:

Node.js Download