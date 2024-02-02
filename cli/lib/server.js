import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import bodyParser from 'body-parser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function start(tokenCallback){
    const app = express()
    const port = 3000

    app.use(bodyParser.text());
    app.use(bodyParser.json());

    app.get('/code/callback', (req, res) => {
        console.log(`code/callback`);
        res.sendFile(path.resolve(`${__dirname}/../frontend/index.html`));
    })

    app.post(`/token`, (req, res) => {
        console.log(`Succesfully got access token: ${req.body}`);
        tokenCallback(req.body);
        res.status(200).send();
        server.close();
    })

    app.use(express.static(path.resolve(`${__dirname}/../frontend`)));


    const server = app.listen(port, () => {
        console.log(`10tx server running as 'http://localhost:${port}'. After successful login, come back here.`)
    })

    server.on('error', function(e) {
        if (e.code === 'EADDRINUSE') {
            console.log (`Port ${3000} is taken. please release it and run again`);
        }
    });
}
const server = { start }
export default server;
