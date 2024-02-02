export default function parseJwt(jwt){
    try {
        const data = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString('utf-8'));
        return data;
    }
    catch (ex) {
        throw new Error (`Error parsing JWT: ${ex.stack}`);
    }
}
