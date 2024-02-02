import fs from 'fs';
import path from 'path';
import chalk from 'chalk';

export default function readPublicKey(publicKeyPath = path.resolve (`${process.cwd()}/keys/public.pem`)) {
    try {
        const pk = fs.readFileSync(path.resolve(publicKeyPath), {encoding: 'utf8'});
        console.log (`Public Key: `)
        console.log(pk);
        return pk;
    }
    catch (ex) {
        console.error (`Error reading public key file from '${publicKeyPath}', please run ${chalk.bold(`as genkeys`)} first`);
    }
}
