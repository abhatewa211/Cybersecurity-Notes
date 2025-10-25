### we use OWASP JUICE SHOP bcoz it is like the copy pf real life web application with vulnerabilities

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image.png)

### It is almost as same as the real application includes payment method too

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%201.png)

- FREE
- Includes security challenges
- CTF In cybersecurity, Capture the Flag (CTF) is **a gamified exercise where participants find and exploit vulnerabilities in systems to retrieve "flags" (pieces of information)**. These competitions are used to test and improve skills in various cybersecurity domains like penetration testing, incident response, and digital forensics
- A community version created by OWASP to get the real life experience and pentesting for applications
- Install through docker , local install , cloud or online demo

 

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%202.png)

## OFFICIAL RESOURCES

[https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)

[https://demo.owasp-juice.shop/#/](https://demo.owasp-juice.shop/#/)  —— live demo

---

---

---

---

---

---

---

---

## Lastly we started JUICE SHOP on 192.168.1.31 : 3000

**we have to start it again and follow the same process of starting like**

**go to opt**

**then juice shop**

**then npm start** 

to avoid this everytime to start the juice shop on the server we have few optional options

## CREATE A START SCRIPT

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%203.png)

or 

## CREATE A SYSTEMD SERVICE

To start the juice shop with serivce that if service is enabled it will get opened after poweron

```jsx
vim /etc/systemd/system/juice-shop.service
```

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%204.png)

check the working directory

```jsx
cd /opt/juice-shop_18.0.0
```

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%205.png)

## service is created ..lets check

```jsx
systemctl daemon-reload
```

```jsx
systemctl enable juice-shop
```

```jsx
systemctl start juice-shop
```

```jsx
systemctl status juice-shop
```

reboot and check again

```jsx
reboot
```

browse the application through server’s IP .

[http://192.168.1.31:3000/](http://192.168.1.31:3000/)

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%206.png)

here we have many shops (applications) to exploit 

we can also use walkthrough by searching them .. but it would be cheating 

so we have to find unknown vulnerabilities to solve ourself 

---

---

---

---

# PHP GURUKUL

[https://phpgurukul.com/](https://phpgurukul.com/)

### This website contains many projects (labs/machine) which we can setup and solve

[https://phpgurukul.com/php-projects-free-downloads/](https://phpgurukul.com/php-projects-free-downloads/)

## Download the free projects

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%207.png)

scroll down to see the details regarding requirements of the project 

i.e php version , some tools ,etc ..

### scroll down to download

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%208.png)

[What is PHP gurukul](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/What%20is%20PHP%20gurukul%20232dcbc1249580a59f31c68541fc146a.md)

we can download different projects to get to know about types of php application development ..

---

---

---

---

[ELMS](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/ELMS%2023bdcbc12495807fa8acc5147864e16b.md)

[GMS](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/GMS%2023bdcbc124958055bfe5c402b46b94d7.md)

---

---

---

---

we have to configure different 10-15 projects

get the project 

exploit it 

and assign for CVE registration

![image.png](OWASP%20JUICE%20SHOP%20service%2022adcbc12495807b9924d5d162b6a8d3/image%209.png)

thankyou