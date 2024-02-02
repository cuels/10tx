export default {
    'development': {
        'apiUrl': () => 'https://api.au10tixservicesdev.com'
    },
    'qa': {
        'apiUrl': () => 'https://api-weu.au10tixservicesqa.com'
    },
    'staging': {
        'apiUrl': region => `https://${region}-api.au10tixservicesstaging.com`
    },
    'production': {
        'apiUrl': region => `https://${region}-api.au10tixservices.com`
    }
}
