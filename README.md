# OAuth 2 in Action

![Cover of OAuth 2 in Action](https://images.manning.com/255/340/resize/book/e/14336f9-6493-46dc-938c-11a34c9d20ac/Richer-OAuth2-HI.png)

https://www.manning.com/books/oauth-2-in-action

## About the book

Think of OAuth 2 like the web version of a valet key. This HTTP-based security protocol allows the users of a service to enable applications to use that service on their behalf without handing over full control. Web and mobile apps can securely access information from other servers for these users, enabling you to give your users functionality and services from other sites. Instead of unsafe password-sharing, OAuth offers a much more secure delegation protocol. OAuth is used everywhere, from large providers like Facebook and Google, to small APIs at startups, and even cloud services, it’s the worldwide standard. OAuth 2 is the must-know security protocol on the web today.

OAuth 2 in Action teaches you practical use and deployment of this protocol from the perspective of a client, authorization server, and resource server. You’ll begin with an overview of OAuth and a look at its components and interactions. Then, using lots of hands-on examples, you’ll build your first OAuth client, followed by an authorization server, and then a protected resource. The second part of the book dives into crucial implementation vulnerability topics. Then you learn about tokens, dynamic client registration, and more advanced topics. This book teaches you to how to distinguish between different OAuth options and choose the right set for your application. By the end of this book, you’ll be able to build and deploy applications that use OAuth on both the client and server sides.

## About the authors

Justin Richer is a systems architect, software engineer, standards editor, and service designer working as an independent consultant. [Antonio Sanso](http://blog.intothesymmetry.com/) works as Security Software Engineer, he is a vulnerability security researcher and an active open source contributor.

## How to Install and Run the Project

### Clone Repository

Using terminal go to directory of your choosing and execute ```git clone https://github.com/oauthinaction/oauth-in-action-code.git```

### Install Dependencies

Repository contains multiple project, each requiring to install its dependencies before executing any code. For each exercise, enter the directory and run ```npm install``` to install dependencies before executing the code.

### Run Project

To execute any file written in JavaScript using node simply run ```node [file_name]``` in terminal for eg. ```node client.js```.  
  
Some examples require to run multiple files concurrently to work properly (for example, the authorization server, client, and resource server components), and it is recommended that each file be executed in its own separate environment, such as in separate terminal windows.

Each service runs on ```localhost``` and is usually available over HTTP.

The usual ports for items is:
* client.js - ```http://localhost:9000/```
* authorizationServer.js - ```http://localhost:9001/```
* protectedResource.js - ```http://localhost:9002/```