console.log ('script loaded');

const { OktaConfig, OktaRequest } = window.oktaAuth;

const oidc = {
        clientId: '0oa2qvxrd5Wd0Xb4c357',
        issuer: `https://login.au10tix.com/oauth2/default`,
        redirectUri: 'http://localhost:3000/code/callback',
        logoutUri: 'http://localhost:3000',
}

if (window.env === 'staging') {
    oidc.clientId = '0oa42svttiIRh0BSP357'
}
else if (window.env === 'production') {
    oidc.clientId = '0oa4lnlm2vhJkWxCN357';
}

const onChange = key => value => {
    console.log (`called with: ${key} = ${value}`)
    switch (key) {
        case 'accessToken':
            console.log('access token: ' + value);
            break;
    }
}

const oktaConfig = new OktaConfig(oidc, 'development');
const oktaReq = new OktaRequest(oktaConfig, onChange, {
    isAuthenticatedCb: value => {
        console.log(`already authentication: ${value}`);
    },
});
oktaReq.onProcessSuccess = async auth => {
    console.log(`onProcessSuccess: ${JSON.stringify(auth, null, '\t')}`);
    try {
        await fetch(`http://localhost:3000/token`,{
            method: 'POST',
            body: auth?.accessToken
        })
        updateUI();
    }
    catch (ex){
        document.body.innerText(`error: ${ex}`);
    }
};

oktaReq.onError = error => {
    console.error(`Auth error: ${JSON.stringify(error, null, '\t')}`);
    updateUI(false, error);
}

oktaReq.onTokenValid = async token => {
    console.log (`onTokenValid: ${token}`);
    try {
        await fetch(`http://localhost:3000/token`,{
            method: 'POST',
            body: token
        })
        updateUI();
    }
    catch (ex){
        document.body.innerText(`error: ${ex}`);
    }
}
console.log (`calling authenticate`);
oktaReq.authenticate();

function updateUI (success = true){
    const contentH1 = document.querySelector('.content h1');
    const contentH3 = document.querySelector('.content h3');
    if (success) {
        contentH1.textContent = `Login Success!`
        contentH3.textContent = `Now you can go back to the 10tx CLI tool to continue...`;
    }
    else {
        contentH1.textContent = `Login failed!`
        contentH3.textContent = `An Error occured, please contact AU10TIX`;
    }

}
