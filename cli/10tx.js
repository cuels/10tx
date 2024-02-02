#!/usr/bin/env node

import inquirer from 'inquirer';
import chalk from 'chalk';
import * as jose from 'jose';
import fs from 'fs';
import path from 'path';
import server from './lib/server.js';
import open from 'open';
import minimist from 'minimist';
import util from './lib/util.js';
import sampleCodes from '../sample-code/index.js';

//load package.json
const packageJson = JSON.parse(fs.readFileSync('./package.json'));
const version = packageJson.version;

const commands = {
    'set-config': (argv) => {
        if (!argv['_'].length) return;

        const config = util.getConfig(true);

        argv['_'].forEach (attr => {
            const [key, value] = attr.split("=");
            config[key] = value;
        })
        fs.writeFileSync(path.resolve (`${process.cwd()}/config.json`), JSON.stringify(config, null, '\t'), {encoding: 'utf8'});
    },
    'genkeys': async () => {
        const { publicKey, privateKey } = await jose.generateKeyPair('PS256');
        const pemPublicKey = await jose.exportSPKI(publicKey);
        const pemPrivateKey = await jose.exportPKCS8(privateKey);
        console.log(pemPublicKey)
        if (fs.existsSync (`${process.cwd()}/keys`)){
            const { answer } = await inquirer.prompt({
                name: 'answer',
                message: `'keys' folder already exists, overwrite (y/n)?`,
                type: 'string'
            })
            if (answer.toLowerCase() === 'n') return;
            fs.rmdirSync(`${process.cwd()}/keys`, {recursive : true});
        }
        fs.mkdirSync (path.resolve(`${process.cwd()}/keys`));
        fs.writeFileSync(path.resolve(`${process.cwd()}/keys/private.pem`), pemPrivateKey);
        fs.writeFileSync(path.resolve(`${process.cwd()}/keys/public.pem`), pemPublicKey);
    },
    'login': async () => {
        const config = util.getConfig();
        if (!config.env) return console.log(`Missing configuration. Please set the environment ('env') and region with the ${chalk.bold('10tx set-config')} command`)
        if (!util.updateEnv(config.env)) return
        return new Promise ((res, rej) => {
            const loginTimeout = setTimeout(() => {
                console.log (`Login timeout (60 seconds).`);
                rej();
            }, 60000)
            server.start(token => {
                clearTimeout(loginTimeout);
                fs.writeFileSync (path.resolve(`${process.cwd()}/token.txt`), token);
                res();
            });

            open('http://localhost:3000', {app: 'chrome'});
        });
    },
    'sendpk': async (argv) => {
        const { keyid, orgid } = argv;
        const config = util.getConfig();
        if (!config.env || !config.region)
            return console.log(`Missing configuration. Please set the environment ('env') and region with the ${chalk.bold('10tx set-config')} command`)


        const publicKeyData = util.readPublicKey();
        const token = util.readAccessToken();

        if (!publicKeyData || !token) return;

        let data;
        try {
            data = util.parseJwt(token);
        }
        catch (ex) {
            return console.error (`Access token invalid: ${ex}`);
        }
        const organizationId = data.clientOrganizationId || data.organization || orgid;
        await util.sendPublicKey({publicKeyData, keyId: keyid, env: config.env, region: config.region, token, organizationId});
    },
    'run-sample': (argv) => {

    },
    'setup': async (argv) => {
        const config = util.getConfig();
        if (!config.env || !config.region) {
            return console.log (`Missing 'env' and 'region' configurations. Please run '10tx set-config command first. Use 10tx --help for details.` );
        }
        console.log ();
        console.log (`1. Generating Private-Public Key pair in '/keys' folder.`);
        await commands.genkeys();
        console.log ();
        console.log (`2. Login to AU10TIX`);

        try {
            await commands.login();
        }
        catch (ex) {return}

        console.log ();
        console.log (`3. Sending public key to AU10TIX.`);

        await commands.sendpk(argv);

        console.log ();
        console.log (`${chalk.bold(`Done!`)} Setup is now complete. Calling workflow API (see ./sample-code/Webapp).`);
        sampleCodes.Webapp();


    },
    'run-sample-code': () => {
        sampleCodes.Webapp();
    },
    'help': () => {
        console.log();
        console.log(chalk.underline(chalk.bold(`AU10TIX Setup Tool (10tx) Help (v. ${version})`)));
        console.log();
        console.log(`${chalk.bold('set-config')} \t\t Sets the configuration of the 10tx tool including environment and region.`);
        console.log();
        console.log(`\t\t\t Options:`)
        console.log(`\t\t\t set-config region=[eus | weu | wus | ejp]`)
        console.log(`\t\t\t set-config env=[staging | production]`)
        console.log();
        console.log(`${chalk.bold('setup')} \t\t\t Runs all the steps (commands below) to setup the integration with AU10TIX, and runs the sample code.`);
        console.log();
        console.log(`${chalk.bold('genkeys')} \t\t Generates Private-Public Key pair in '/keys' folder.`);
        console.log();
        console.log(`${chalk.bold('login')} \t\t\t Logs in to AU10TIX to get an Access Token.`);
        console.log();
        console.log(`${chalk.bold('sendpk')} \t\t\t Sends the Public Key to AU10TIX.`);
        console.log();
        console.log(`\t\t\t --keyid [Optional]`);
        console.log(`\t\t\t Key ID is required when creating a JWT (default: 'key1').`);
        console.log();
        console.log(`${chalk.bold('run-sample-code')} \t Runs Workflow API sample code. Creates a Webapp + IDV workflow request, and opens it in a browser.`);
        console.log();
        console.log();
        console.log(`For any questions please contact: support@au10tix.com`)
        console.log();
    }
}

if (['--version', '-v'].includes(process.argv[2])){
    console.log(version);
}
else if (['--help', '-h'].includes(process.argv[2])) {
    commands.help();
}
else if (!(process.argv[2] in commands)){
    console.log(`Unknown command. Please use '10tx --help' for help.`);
}
else {
    commands[process.argv[2]](minimist(process.argv.slice(3)));
}
