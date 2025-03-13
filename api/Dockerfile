# Dockerfile

FROM node:16.15-alpine3.14
RUN mkdir /opt/app
COPY . /opt/app
WORKDIR /opt/app
RUN adduser -S app
RUN npm install
RUN npm install --save pm2
RUN chown -R app /opt/app
USER app
EXPOSE 4000
CMD [ "npm", "start" ]