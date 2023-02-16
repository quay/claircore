# testdata

## sample-nodejs-app.tar

This layer is derived from a sample NodeJS 16 image
from https://nodejs.org/en/docs/guides/nodejs-docker-webapp/.

It was created by the following Dockerfile:

```
FROM node:16

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
```

The related package.json is as follows:

```
{
  "name": "docker_web_app",
  "version": "1.0.0",
  "description": "Node.js on Docker",
  "author": "First Last <first.last@example.com>",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.16.1"
  }
}
```

The layer tar was extracted from the image (top layer).
