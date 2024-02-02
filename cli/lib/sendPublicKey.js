import fs from 'fs';
import path from 'path';
import config from '../../urls.js';
import axios from 'axios';

export default async function sendPublicKey ({publicKeyData, keyId = 'key1', env, region, token, organizationId}) {
    if (env === 'qa' && !organizationId) {
        organizationId = 326;
    }
    if (!organizationId)
        return console.log(`Couldn't resolve Organization ID`);

    fs.writeFileSync(path.resolve(`${process.cwd()}/keyId.txt`), keyId, {encoding: 'utf8'});

    console.log(`Sending your public key to AU10TIX...`);
    try {
        const url = `${config[env].apiUrl(region)}/cm/v1/applications/${organizationId}`;
        console.log(url)
        const response = await axios(url, {
            method: 'PATCH',
            data: {
                id: keyId,
                publicKey: publicKeyData,
            },
            headers: {
                'content-type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
        });

        console.log (`Saving your clientId '${response.data.clientId}' to ./clientId.txt`);
        fs.writeFileSync (`${process.cwd()}/clientId.txt`, response.data.clientId, {encoding: 'utf8'});

        console.log('Public key was succesfully sent to AU10TIX!');
    } catch (error) {
        const {response} = error;

        if (response) {
            const {data, status} = response;
            console.error(`Error in sending public key. status: ${status}, data: ${JSON.stringify(data)}`);
        } else {
            console.error(`Error in sending public key: ${error}`);
        }
    }
}
