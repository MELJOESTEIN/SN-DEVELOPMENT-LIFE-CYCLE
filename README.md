<!-- ABOUT THE PROJECT -->
## About The Project
**The Count of Money**
![Count of Money Anonymous interface][product-screenshot]
&nbsp;
# **Introduction**
"The Count of Money" is a web application, which allows you to keep informed and beat the coins.
It is composed of 3 profiles:
   * The Anonymous
   * The Users 
   * The Administrator
&nbsp;
## **Project context**
This application allows visitors to be informed about the status and variations of cryptocurrencies. It also allows them to read articles related to cryptocurrencies in order to get informed.

Three levels of access are managed with specific privileges:
* anonymous access:
    * have access to the N most popular cryptocurrency courses as well as their evolution (trend and
    percentage) since the opening
    The list of the N most popular cryptocurrencies is defined by an administrator
    * can check the latest K articles in the press
    K is set by an administrator.
* user access:
    * must first create an account
    * user can authenticate by email/password or by Oauth2 (both MUST be implemented)
    * can determine their own list(*) of crypto-currencies
    * can define keywords to refine the press review
    * can change their preferences on their profile page
* administrator access:
    * manage global application preferences
    * list of cryptocurrencies that can be consulted
    * list of sources (RSS feed) to constitute the press review
    (he list of eligible crypto-currencies is established by an an administrator.
    By default, this list is the same as for an anonymous user.)
&nbsp;

### Built With


* [![Bootstrap][Bootstrap.com]][Bootstrap-url]
* [![Vue][Vue.js]][Vue-url]
* 💻 VS Code
* NodeJs

### Prerequisites

Install :
* Git
```sh
sudo apt-get install git
```
* NodeJs
```sh
sudo apt-get install -y nodejs
```
* MongoDB
```sh
sudo apt-get install gnupg
```
* Vuejs 3
```sh
npm init vue@latest
```
### How to Run
 
1. Run the following command to run the entire project with docker.
```sh
$ docker-compose up --build
```
2. Run the following command to run the front-end
```sh
$ npm install
$ npm run dev
```
3. Run the following command to run the back-end (By being in /api because the .env is in this location)
```sh
$ npm install
$ node database/create_db.js
$ npm run dev
```
## Table of contents
> * [The Count of Money](#TheCountofMoney)
>   * [Introduction](#introduction)
>   * [Project context](#project-context)
>   * [Built With](#BuiltWith)
>   * [Prerequisites](#Prerequisites)
>   * [How to Run](#HowtoRun)
> * [Members](#Members)
&nbsp;

<!-- CONTACT -->


<!-- IMAGES -->
[product-screenshot]: docs/interface_Money.png
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
