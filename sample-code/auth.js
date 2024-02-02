import jwtBuilder from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import urls from '../urls.js';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getClientId () {
    const clientId = fs.readFileSync(`${process.cwd()}/clientId.txt`, {encoding: 'utf8'});
    return clientId;
}

function getKeyId(){
    const keyId = fs.readFileSync(`${process.cwd()}/keyId.txt`, {encoding: 'utf8'});
    return keyId;
}

function getPrivateKey() {
    const privateKey = fs.readFileSync(`${process.cwd()}/keys/private.pem`, {encoding: 'utf8'});
    return privateKey;
}

function getConfig() {
    const config = fs.readFileSync('./config.json');
    return JSON.parse(config);
}

function getPayload() {
    const clientId = getClientId();
    return {
        "sub": clientId,
        "iss": clientId,
        "aud": "https://login.au10tix.com/oauth2/aus3mlts5sbe9WD8V357/v1/token",
        "exp": Math.ceil(Date.now() / 1000) + 3500
    };
}

function getOptions(){
    const keyId = getKeyId();
    return {
        algorithm: "RS256",
        header: {
            "kid": keyId
        }
    };
}

function createJWT (){
    const privateKeyPEM = getPrivateKey();
    const payload = getPayload();
    const options = getOptions();
    const privateKey = crypto.createPrivateKey({ key: privateKeyPEM });
    const jwt = jwtBuilder.sign(payload, privateKey, options);
    console.log(`Created JWT: ${jwt}`);
    return jwt;
}

function parseJwt(jwt){
    try {
        const data = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString('utf-8'));
        return data;
    }
    catch (ex) {
        throw new Error (`Error parsing JWT: ${ex.stack}`);
    }
}

function isExpired(accessToken) {
    const jwt = parseJwt(accessToken);
    const expirationDate = new Date (jwt.iat);
    if (Date.now > expirationDate.getTime()) {
        console.log (`Access token expired.`);
        return true;
    }
    return false;
}

async function getAccessToken() {
    const { env, region } = getConfig();
    const url = `${urls[env].apiUrl(region)}/oauth2/v1/token`;
    const jwt = createJWT();
    const params = new URLSearchParams();
    params.append('client_assertion', jwt);
    params.append('scope', 'workflow:api');

    try {
        console.log (`Getting an access token from: '${url}'`);
        const response = await axios.post(url, params);
        return response.data.access_token;
    }
    catch (ex) {
        const {response} = ex;
        if (response) {
            const {data, status} = response;
            console.error(`Error getting an access token. status: ${status}, data: ${JSON.stringify(data)}`);
        } else {
            console.error(`Error getting an access token: ${ex}`);
        }
    }
}

let cachedAccessToken;

export default async function getAu10tixAccessToken () {
    if (!cachedAccessToken || isExpired(cachedAccessToken)){
        cachedAccessToken = await getAccessToken();
        if (!cachedAccessToken) return;
        console.log (`Stored access token in cache`);
        return cachedAccessToken;
    }
    else {
        console.log (`Retrieved access token from cache`);
        return cachedAccessToken;
    }
}
