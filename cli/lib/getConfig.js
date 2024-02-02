import fs from 'fs';
import path from 'path';

export default function getConfig(dontPrintError) {
    let config = {};
    try {
        console.log (`path: ${path.resolve('./config.json')}`);
        config = fs.readFileSync('./config.json');
        config = JSON.parse(config);
    }
    catch (ex) {
        if (!dontPrintError)
            console.log(`Error reading './config.json'. please make sure you've created it with 'set-config' command.`);
    }
    finally {
        return config;
    }
}
