import fs from 'fs';
import path from 'path';
import chalk from 'chalk';

export default function readAccessToken() {
    try {
        const token = fs.readFileSync(path.resolve(`${process.cwd()}/token.txt`), {encoding: 'utf8'});
        console.log (`Access Token: `)
        console.log(token);
        console.log();
        return token;
    }
    catch (ex) {
        console.error (`Error reading access token, please run ${chalk.bold(`as login`)} first`);
    }
}
