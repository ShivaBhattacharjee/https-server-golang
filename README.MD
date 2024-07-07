

<br/>
<h3 align="center">HTTPS-SERVER-GO-LANG</h3>

<div align="center" >

![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![HTTP/2](https://img.shields.io/badge/HTTP/2-339933?style=for-the-badge&logo=http2&logoColor=white)
![GitHub repo size](https://img.shields.io/github/repo-size/ShivaBhattacharjee/https-server-golang)

</div>

<p align="center">
  A secure HTTPS server written in Go with HTTP/2 support.
  <br/>
  <br/>
  <a href="https://github.com/ShivaBhattacharjee/https-server-golang/issues">Report Bug</a>
  .
  <a href="https://github.com/ShivaBhattacharjee/https-server-golang/issues">Request Feature</a>
</p>

## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [Features](#features)
- [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)


## Features

- HTTP/2 support for improved performance
- Rate limiting middleware to manage request traffic
- Security headers middleware for enhanced security
- Logging middleware to track requests
- Customizable static file serving and dynamic routing

## Built With



- [Go](https://golang.org)
- [HTTP/2](https://http2.github.io)
- [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- Go installed locally
- Certificates for HTTPS setup (e.g., self-signed or from a certificate authority)

### Installation

Clone the repo:

```bash
git clone https://github.com/ShivaBhattacharjee/https-server-golang
```

```bash
cd https-server-golang
```

```bash
sudo go run src/main.go
```

## Usage
Visit http://localhost:443 in your browser to see your HTTPS server in action.

## Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

 - Fork the Project
- Create your Feature Branch (git checkout -b feature/AmazingFeature)
- Commit your Changes (git commit -m 'Add some AmazingFeature')
- Push to the Branch (git push origin feature/AmazingFeature)
- Open a Pull Request

## License
Distributed under the [Apache License 2.0](https://github.com/ShivaBhattacharjee/https-server-golang/blob/main/LICENSE). See LICENSE for more information.