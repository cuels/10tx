import getAu10tixAccessToken from '../auth.js';
import axios from 'axios';
import urls from '../../urls.js';
import open from 'open';
import fs from "fs";

function getConfig() {
    const config = fs.readFileSync('./config.json');
    return JSON.parse(config);
}

function openLinkIn3(url, times = 3) {
    if (times === 0){
        console.log (`Enjoy...`)
        open (url);
        return;
    }
    console.log(`Opening Webapp link in ${times}`);
    setTimeout(() => openLinkIn3(url, --times), 1000);
}

async function run() {

    console.log(`AU10TIX Webapp Sample Code`);
    console.log();
    console.log(`1. Preparing an Access Token:`);
    console.log();
    const accessToken = await getAu10tixAccessToken();
    if (!accessToken) return;
    console.log (`Got access token: ${accessToken}`);
    console.log();

    const { env, region } = getConfig();
    const url = `${urls[env].apiUrl(region)}/workflow/v1/workflows/person/Au10tix201`;
    console.log(`2. Calling AU10TIX to create a webapp link: ${url}`);
    const body = {
        serviceOptions: {
            secureme: {
                requestTypes: {
                    idFront: ['camera', 'file'],
                    idBack: ['camera', 'file'],
                    faceCompare: ['camera', 'file']
                }
            }
        }
    }
    const options = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        }
    }

    try {
        const response = await axios.post(url, body, options);
        console.log (`Got a webapp link. response: `);
        console.log (JSON.stringify(response.data, null, "\t"));
        console.log()
        openLinkIn3(response.data.response.securemeLink);
    }
    catch (ex){
        const {response} = ex;
        if (response) {
            const {data, status} = response;
            console.error(`Error creating webapp link. status: ${status}, data: ${JSON.stringify(data)}`);
        } else {
            console.error(`Error creating webapp link: ${ex}`);
        }
    }

}

export default run;
