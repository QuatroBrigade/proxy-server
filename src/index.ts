import { createProxyMiddleware, Filter, Options, RequestHandler } from 'http-proxy-middleware';
import { createLogger, format, transports } from 'winston'
import { format as fechaFormat } from 'fecha'
import express, { Express, NextFunction, Request, Response, json, urlencoded } from 'express'
import dotenv from 'dotenv'
import vhost from "vhost";
import fs from 'fs';
import tls from 'tls';
import https from 'https';
import http from 'http';

export const logger = createLogger({
    transports: [
        new transports.Console(),
        new transports.File({
            dirname: "logs",
            filename: "log-" + fechaFormat(new Date(), 'DD-MM-YYYY') + ".log",
        }),
    ],
    format: format.combine(
        format.timestamp({ format: 'DD-MM-YYYY HH:mm:ss.SSS' }),
        format.printf(({ timestamp, level, message, service }) => {
            return `[${timestamp}] ${service} ${level}: ${message}`;
        })
    ),
    defaultMeta: {
        service: "MainService",
    },
});

logger.info("------------- START OF LOG FILE -------------")

dotenv.config();

const app: Express = express()
const port = process.env.MAIN_PORT

app.use(urlencoded({ extended: true }))
app.use(json())
app.set('trust proxy', true)

app.use(vhost('townsy.tech', createProxyMiddleware({
    target: 'http://localhost:3000/',
    changeOrigin: true,
})))

app.use(vhost('api-1.townsy.tech', createProxyMiddleware({
    target: 'http://localhost:65500/',
    changeOrigin: true,
})))

app.use(vhost('api-2.townsy.tech', createProxyMiddleware({
    target: 'http://localhost:88/',
    changeOrigin: true,
})))

const certs = {
    "townsy.tech": {
        key: '/etc/letsencrypt/live/townsy.tech/privkey.pem',
        cert: '/etc/letsencrypt/live/townsy.tech/fullchain.pem'
    },
    "api-1.townsy.tech": {
        key: '/etc/letsencrypt/live/api-1.townsy.tech/privkey.pem',
        cert: '/etc/letsencrypt/live/api-1.ttownsy.tech/fullchain.pem'
    },
    "api-2.townsy.tech": {
        key: '/etc/letsencrypt/live/api-1.townsy.tech/privkey.pem',
        cert: '/etc/letsencrypt/live/api-1.ttownsy.tech/fullchain.pem'
    },
    "api-3.townsy.tech": {
        key: '/etc/letsencrypt/live/api-1.townsy.tech/privkey.pem',
        cert: '/etc/letsencrypt/live/api-1.ttownsy.tech/fullchain.pem'
    },
}

const getSecureContexts = (certs: any) => {

    if (!certs || Object.keys(certs).length === 0) {
        throw new Error("Any certificate wasn't found.");
    }

    const certsToReturn: any = {};

    for (const serverName of Object.keys(certs)) {
        const appCert = certs[serverName];

        try {
            certsToReturn[serverName] = tls.createSecureContext({
                key: fs.readFileSync(appCert.key),
                cert: fs.readFileSync(appCert.cert),
                // If the 'ca' option is not given, then node.js will use the default
                ca: appCert.ca ? sslCADecode(
                    fs.readFileSync(appCert.ca, "utf8"),
                ) : undefined,
            });
        } catch (error) {
            console.log(error)
            console.log("Could not create certificate for server name " + serverName)
        }
    }

    return certsToReturn;
}

// if CA contains more certificates it will be parsed to array
const sslCADecode = (source: any) => {

    if (!source || typeof (source) !== "string") {
        return [];
    }

    return source.split(/-----END CERTIFICATE-----[\s\n]+-----BEGIN CERTIFICATE-----/)
        .map((value, index: number, array) => {
            if (index) {
                value = "-----BEGIN CERTIFICATE-----" + value;
            }
            if (index !== array.length - 1) {
                value = value + "-----END CERTIFICATE-----";
            }
            value = value.replace(/^\n+/, "").replace(/\n+$/, "");
            return value;
        });
}

const secureContexts = getSecureContexts(certs)

const options = {
    // A function that will be called if the client supports SNI TLS extension.
    SNICallback: (servername: any, cb: any) => {

        const ctx = secureContexts[servername];

        if (!ctx) {
            console.log(`Not found SSL certificate for host: ${servername} at: ` + new Date().getTime());
        } else {
            console.log(`SSL certificate has been found and assigned to ${servername} at: ` + new Date().getTime());
        }

        if (cb) {
            cb(null, ctx);
        } else {
            return ctx;
        }
    },
};

https.createServer(options, app).listen(process.env.MAIN_PORT, function () {
    console.log('HTTPS App is listening on port ' + process.env.MAIN_PORT);
});

let httpApp = express();

httpApp.use(vhost('townsy.tech', function (req, res, next) {
    res.redirect('https://townsy.tech/')
}));

httpApp.use(vhost('api-1.townsy.tech', function (req, res, next) {
    res.redirect('https://api-1.townsy.tech/')
}));

httpApp.use(vhost('api-2.townsy.tech', function (req, res, next) {
    res.redirect('https://api-2.townsy.tech/')
}));

httpApp.use(vhost('api-3.townsy.tech', function (req, res, next) {
    res.redirect('https://api-3.townsy.tech/')
}));

http.createServer(httpApp).listen(80, function () {
    console.log('HTTP App is listening on port 80!');
})

httpApp.get('*', function (req, res) {
    return res.status(404).send({ error: 404, message: 'This page does not exist! Please, return to main page!' })
});