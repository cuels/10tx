import fs from 'fs';
import path from 'path';

export default function updateEnv(env) {
    if (!['development', 'qa', 'staging', 'production'].includes (env)) {
        console.log (`Environment '${env}' is invalid`);
        return false;
    }

    fs.writeFileSync(path.resolve(`./cli/frontend/env.js`), `window.env='${env}'`, {encoding: 'utf8'});
    return true;
}
