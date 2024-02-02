class OktaConfig {
    constructor(oidc, env) {
        this.oidc = oidc;
        this.env = env;
    }
}

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __classPrivateFieldGet(receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
}

function __classPrivateFieldSet(receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
}

class OktaModel {
    constructor() {
        this.isAuthenticated = false;
        this.authenticationError = null;
        this.userData = {};
        this.clientOrganization = {};
        this.idToken = null;
        this.accessToken = null;
        this.isAu10tixAdmin = false;
        this.tokenData = null;
        this.clientOrganizations = {};
    }
}

function generateRandomString() {
    var array = new Uint32Array(28);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}
// Return the base64-urlencoded sha256 hash for the PKCE challenge
function pkceChallengeFromVerifier(v) {
    return __awaiter(this, void 0, void 0, function* () {
        const hashed = yield sha256(v);
        return base64urlencode(hashed);
    });
}
// Calculate the SHA256 hash of the input text.
// Returns a promise that resolves to an ArrayBuffer
function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
}
// Base64-urlencodes the input string
function base64urlencode(str) {
    // Convert the ArrayBuffer to string using Uint8 array to convert to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
function parseToken(token) {
    return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}
function extractUserData(jwtData) {
    return {
        id: jwtData.uid,
        name: `${jwtData.firstName} ${jwtData.lastName}`,
        firstName: jwtData.firstName,
        lastName: jwtData.lastName,
        email: jwtData.email || jwtData.sub,
        groups: jwtData.groups,
        urls: jwtData.nickname,
        organization: jwtData.organization,
    };
}
function getUniqueOrganizations(userData) {
    var _a, _b;
    const uniquGroups = new Set((_b = (_a = userData === null || userData === void 0 ? void 0 : userData.groups) === null || _a === void 0 ? void 0 : _a.filter(group => group.includes('cm'))) === null || _b === void 0 ? void 0 : _b.map(group => `${group.split('.')[0]}.${group.split('.')[1]}`));
    return Array.from(uniquGroups);
}
// oktaModelProxy is a function that wrap the object with getter and setter
// this function helps to create getter and setter dynamically , and add custom callback on setter
const oktaModelProxy = (obj) => new Proxy(obj, {
    get(target, name, receiver) {
        let rv = Reflect.get(target, name, receiver);
        return rv;
    },
    set(target, name, value, receiver) {
        const callback = target[`${name}Cb`];
        if (callback)
            callback(value);
        return Reflect.set(target, name, value, receiver);
    },
});

const AUTHENTICATION_ERRORS = {
    NOT_ASSIGNED: "NOT_ASSIGNED",
    JWT_PARSING_ERROR: "JWT_PARSING_ERROR",
    ERROR: "AUTHENTICATION_ERROR",
};

const logger = {
    log: msg => console.log(`[API] ${msg}`),
    error: msg => console.error(`[API] ${msg}`),
};
function request(url, options = {}, onUnauthorized) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let res = yield fetch(url, options);
            let body;
            const contentType = res.headers.get('content-type');
            if (contentType && contentType.indexOf('application/json') !== -1) {
                body = yield res.json();
            }
            else {
                body = yield res.text();
            }
            if ((res.status >= 200 && res.status < 400) || res.status === 404) {
                return body;
            }
            else {
                let error = `Application Error: ${JSON.stringify(body, null, '\t')}`;
                if (res.status === 401)
                    onUnauthorized();
                let err = {
                    message: error,
                    status: res.status,
                    statusText: res.statusText,
                };
                throw err;
            }
        }
        catch (ex) {
            logger.error(ex);
            throw ex;
        }
    });
}

var queryString = {};

var strictUriEncode = str => encodeURIComponent(str).replace(/[!'()*]/g, x => `%${x.charCodeAt(0).toString(16).toUpperCase()}`);

var token = '%[a-f0-9]{2}';
var singleMatcher = new RegExp(token, 'gi');
var multiMatcher = new RegExp('(' + token + ')+', 'gi');

function decodeComponents(components, split) {
	try {
		// Try to decode the entire string first
		return decodeURIComponent(components.join(''));
	} catch (err) {
		// Do nothing
	}

	if (components.length === 1) {
		return components;
	}

	split = split || 1;

	// Split the array in 2 parts
	var left = components.slice(0, split);
	var right = components.slice(split);

	return Array.prototype.concat.call([], decodeComponents(left), decodeComponents(right));
}

function decode(input) {
	try {
		return decodeURIComponent(input);
	} catch (err) {
		var tokens = input.match(singleMatcher);

		for (var i = 1; i < tokens.length; i++) {
			input = decodeComponents(tokens, i).join('');

			tokens = input.match(singleMatcher);
		}

		return input;
	}
}

function customDecodeURIComponent(input) {
	// Keep track of all the replacements and prefill the map with the `BOM`
	var replaceMap = {
		'%FE%FF': '\uFFFD\uFFFD',
		'%FF%FE': '\uFFFD\uFFFD'
	};

	var match = multiMatcher.exec(input);
	while (match) {
		try {
			// Decode as big chunks as possible
			replaceMap[match[0]] = decodeURIComponent(match[0]);
		} catch (err) {
			var result = decode(match[0]);

			if (result !== match[0]) {
				replaceMap[match[0]] = result;
			}
		}

		match = multiMatcher.exec(input);
	}

	// Add `%C2` at the end of the map to make sure it does not replace the combinator before everything else
	replaceMap['%C2'] = '\uFFFD';

	var entries = Object.keys(replaceMap);

	for (var i = 0; i < entries.length; i++) {
		// Replace all decoded components
		var key = entries[i];
		input = input.replace(new RegExp(key, 'g'), replaceMap[key]);
	}

	return input;
}

var decodeUriComponent = function (encodedURI) {
	if (typeof encodedURI !== 'string') {
		throw new TypeError('Expected `encodedURI` to be of type `string`, got `' + typeof encodedURI + '`');
	}

	try {
		encodedURI = encodedURI.replace(/\+/g, ' ');

		// Try the built in decoder first
		return decodeURIComponent(encodedURI);
	} catch (err) {
		// Fallback to a more advanced decoder
		return customDecodeURIComponent(encodedURI);
	}
};

var splitOnFirst = (string, separator) => {
	if (!(typeof string === 'string' && typeof separator === 'string')) {
		throw new TypeError('Expected the arguments to be of type `string`');
	}

	if (separator === '') {
		return [string];
	}

	const separatorIndex = string.indexOf(separator);

	if (separatorIndex === -1) {
		return [string];
	}

	return [
		string.slice(0, separatorIndex),
		string.slice(separatorIndex + separator.length)
	];
};

var filterObj = function (obj, predicate) {
	var ret = {};
	var keys = Object.keys(obj);
	var isArr = Array.isArray(predicate);

	for (var i = 0; i < keys.length; i++) {
		var key = keys[i];
		var val = obj[key];

		if (isArr ? predicate.indexOf(key) !== -1 : predicate(key, val, obj)) {
			ret[key] = val;
		}
	}

	return ret;
};

(function (exports) {
	const strictUriEncode$1 = strictUriEncode;
	const decodeComponent = decodeUriComponent;
	const splitOnFirst$1 = splitOnFirst;
	const filterObject = filterObj;

	const isNullOrUndefined = value => value === null || value === undefined;

	const encodeFragmentIdentifier = Symbol('encodeFragmentIdentifier');

	function encoderForArrayFormat(options) {
		switch (options.arrayFormat) {
			case 'index':
				return key => (result, value) => {
					const index = result.length;

					if (
						value === undefined ||
						(options.skipNull && value === null) ||
						(options.skipEmptyString && value === '')
					) {
						return result;
					}

					if (value === null) {
						return [...result, [encode(key, options), '[', index, ']'].join('')];
					}

					return [
						...result,
						[encode(key, options), '[', encode(index, options), ']=', encode(value, options)].join('')
					];
				};

			case 'bracket':
				return key => (result, value) => {
					if (
						value === undefined ||
						(options.skipNull && value === null) ||
						(options.skipEmptyString && value === '')
					) {
						return result;
					}

					if (value === null) {
						return [...result, [encode(key, options), '[]'].join('')];
					}

					return [...result, [encode(key, options), '[]=', encode(value, options)].join('')];
				};

			case 'colon-list-separator':
				return key => (result, value) => {
					if (
						value === undefined ||
						(options.skipNull && value === null) ||
						(options.skipEmptyString && value === '')
					) {
						return result;
					}

					if (value === null) {
						return [...result, [encode(key, options), ':list='].join('')];
					}

					return [...result, [encode(key, options), ':list=', encode(value, options)].join('')];
				};

			case 'comma':
			case 'separator':
			case 'bracket-separator': {
				const keyValueSep = options.arrayFormat === 'bracket-separator' ?
					'[]=' :
					'=';

				return key => (result, value) => {
					if (
						value === undefined ||
						(options.skipNull && value === null) ||
						(options.skipEmptyString && value === '')
					) {
						return result;
					}

					// Translate null to an empty string so that it doesn't serialize as 'null'
					value = value === null ? '' : value;

					if (result.length === 0) {
						return [[encode(key, options), keyValueSep, encode(value, options)].join('')];
					}

					return [[result, encode(value, options)].join(options.arrayFormatSeparator)];
				};
			}

			default:
				return key => (result, value) => {
					if (
						value === undefined ||
						(options.skipNull && value === null) ||
						(options.skipEmptyString && value === '')
					) {
						return result;
					}

					if (value === null) {
						return [...result, encode(key, options)];
					}

					return [...result, [encode(key, options), '=', encode(value, options)].join('')];
				};
		}
	}

	function parserForArrayFormat(options) {
		let result;

		switch (options.arrayFormat) {
			case 'index':
				return (key, value, accumulator) => {
					result = /\[(\d*)\]$/.exec(key);

					key = key.replace(/\[\d*\]$/, '');

					if (!result) {
						accumulator[key] = value;
						return;
					}

					if (accumulator[key] === undefined) {
						accumulator[key] = {};
					}

					accumulator[key][result[1]] = value;
				};

			case 'bracket':
				return (key, value, accumulator) => {
					result = /(\[\])$/.exec(key);
					key = key.replace(/\[\]$/, '');

					if (!result) {
						accumulator[key] = value;
						return;
					}

					if (accumulator[key] === undefined) {
						accumulator[key] = [value];
						return;
					}

					accumulator[key] = [].concat(accumulator[key], value);
				};

			case 'colon-list-separator':
				return (key, value, accumulator) => {
					result = /(:list)$/.exec(key);
					key = key.replace(/:list$/, '');

					if (!result) {
						accumulator[key] = value;
						return;
					}

					if (accumulator[key] === undefined) {
						accumulator[key] = [value];
						return;
					}

					accumulator[key] = [].concat(accumulator[key], value);
				};

			case 'comma':
			case 'separator':
				return (key, value, accumulator) => {
					const isArray = typeof value === 'string' && value.includes(options.arrayFormatSeparator);
					const isEncodedArray = (typeof value === 'string' && !isArray && decode(value, options).includes(options.arrayFormatSeparator));
					value = isEncodedArray ? decode(value, options) : value;
					const newValue = isArray || isEncodedArray ? value.split(options.arrayFormatSeparator).map(item => decode(item, options)) : value === null ? value : decode(value, options);
					accumulator[key] = newValue;
				};

			case 'bracket-separator':
				return (key, value, accumulator) => {
					const isArray = /(\[\])$/.test(key);
					key = key.replace(/\[\]$/, '');

					if (!isArray) {
						accumulator[key] = value ? decode(value, options) : value;
						return;
					}

					const arrayValue = value === null ?
						[] :
						value.split(options.arrayFormatSeparator).map(item => decode(item, options));

					if (accumulator[key] === undefined) {
						accumulator[key] = arrayValue;
						return;
					}

					accumulator[key] = [].concat(accumulator[key], arrayValue);
				};

			default:
				return (key, value, accumulator) => {
					if (accumulator[key] === undefined) {
						accumulator[key] = value;
						return;
					}

					accumulator[key] = [].concat(accumulator[key], value);
				};
		}
	}

	function validateArrayFormatSeparator(value) {
		if (typeof value !== 'string' || value.length !== 1) {
			throw new TypeError('arrayFormatSeparator must be single character string');
		}
	}

	function encode(value, options) {
		if (options.encode) {
			return options.strict ? strictUriEncode$1(value) : encodeURIComponent(value);
		}

		return value;
	}

	function decode(value, options) {
		if (options.decode) {
			return decodeComponent(value);
		}

		return value;
	}

	function keysSorter(input) {
		if (Array.isArray(input)) {
			return input.sort();
		}

		if (typeof input === 'object') {
			return keysSorter(Object.keys(input))
				.sort((a, b) => Number(a) - Number(b))
				.map(key => input[key]);
		}

		return input;
	}

	function removeHash(input) {
		const hashStart = input.indexOf('#');
		if (hashStart !== -1) {
			input = input.slice(0, hashStart);
		}

		return input;
	}

	function getHash(url) {
		let hash = '';
		const hashStart = url.indexOf('#');
		if (hashStart !== -1) {
			hash = url.slice(hashStart);
		}

		return hash;
	}

	function extract(input) {
		input = removeHash(input);
		const queryStart = input.indexOf('?');
		if (queryStart === -1) {
			return '';
		}

		return input.slice(queryStart + 1);
	}

	function parseValue(value, options) {
		if (options.parseNumbers && !Number.isNaN(Number(value)) && (typeof value === 'string' && value.trim() !== '')) {
			value = Number(value);
		} else if (options.parseBooleans && value !== null && (value.toLowerCase() === 'true' || value.toLowerCase() === 'false')) {
			value = value.toLowerCase() === 'true';
		}

		return value;
	}

	function parse(query, options) {
		options = Object.assign({
			decode: true,
			sort: true,
			arrayFormat: 'none',
			arrayFormatSeparator: ',',
			parseNumbers: false,
			parseBooleans: false
		}, options);

		validateArrayFormatSeparator(options.arrayFormatSeparator);

		const formatter = parserForArrayFormat(options);

		// Create an object with no prototype
		const ret = Object.create(null);

		if (typeof query !== 'string') {
			return ret;
		}

		query = query.trim().replace(/^[?#&]/, '');

		if (!query) {
			return ret;
		}

		for (const param of query.split('&')) {
			if (param === '') {
				continue;
			}

			let [key, value] = splitOnFirst$1(options.decode ? param.replace(/\+/g, ' ') : param, '=');

			// Missing `=` should be `null`:
			// http://w3.org/TR/2012/WD-url-20120524/#collect-url-parameters
			value = value === undefined ? null : ['comma', 'separator', 'bracket-separator'].includes(options.arrayFormat) ? value : decode(value, options);
			formatter(decode(key, options), value, ret);
		}

		for (const key of Object.keys(ret)) {
			const value = ret[key];
			if (typeof value === 'object' && value !== null) {
				for (const k of Object.keys(value)) {
					value[k] = parseValue(value[k], options);
				}
			} else {
				ret[key] = parseValue(value, options);
			}
		}

		if (options.sort === false) {
			return ret;
		}

		return (options.sort === true ? Object.keys(ret).sort() : Object.keys(ret).sort(options.sort)).reduce((result, key) => {
			const value = ret[key];
			if (Boolean(value) && typeof value === 'object' && !Array.isArray(value)) {
				// Sort object keys1, not values
				result[key] = keysSorter(value);
			} else {
				result[key] = value;
			}

			return result;
		}, Object.create(null));
	}

	exports.extract = extract;
	exports.parse = parse;

	exports.stringify = (object, options) => {
		if (!object) {
			return '';
		}

		options = Object.assign({
			encode: true,
			strict: true,
			arrayFormat: 'none',
			arrayFormatSeparator: ','
		}, options);

		validateArrayFormatSeparator(options.arrayFormatSeparator);

		const shouldFilter = key => (
			(options.skipNull && isNullOrUndefined(object[key])) ||
			(options.skipEmptyString && object[key] === '')
		);

		const formatter = encoderForArrayFormat(options);

		const objectCopy = {};

		for (const key of Object.keys(object)) {
			if (!shouldFilter(key)) {
				objectCopy[key] = object[key];
			}
		}

		const keys = Object.keys(objectCopy);

		if (options.sort !== false) {
			keys.sort(options.sort);
		}

		return keys.map(key => {
			const value = object[key];

			if (value === undefined) {
				return '';
			}

			if (value === null) {
				return encode(key, options);
			}

			if (Array.isArray(value)) {
				if (value.length === 0 && options.arrayFormat === 'bracket-separator') {
					return encode(key, options) + '[]';
				}

				return value
					.reduce(formatter(key), [])
					.join('&');
			}

			return encode(key, options) + '=' + encode(value, options);
		}).filter(x => x.length > 0).join('&');
	};

	exports.parseUrl = (url, options) => {
		options = Object.assign({
			decode: true
		}, options);

		const [url_, hash] = splitOnFirst$1(url, '#');

		return Object.assign(
			{
				url: url_.split('?')[0] || '',
				query: parse(extract(url), options)
			},
			options && options.parseFragmentIdentifier && hash ? {fragmentIdentifier: decode(hash, options)} : {}
		);
	};

	exports.stringifyUrl = (object, options) => {
		options = Object.assign({
			encode: true,
			strict: true,
			[encodeFragmentIdentifier]: true
		}, options);

		const url = removeHash(object.url).split('?')[0] || '';
		const queryFromUrl = exports.extract(object.url);
		const parsedQueryFromUrl = exports.parse(queryFromUrl, {sort: false});

		const query = Object.assign(parsedQueryFromUrl, object.query);
		let queryString = exports.stringify(query, options);
		if (queryString) {
			queryString = `?${queryString}`;
		}

		let hash = getHash(object.url);
		if (object.fragmentIdentifier) {
			hash = `#${options[encodeFragmentIdentifier] ? encode(object.fragmentIdentifier, options) : object.fragmentIdentifier}`;
		}

		return `${url}${queryString}${hash}`;
	};

	exports.pick = (input, filter, options) => {
		options = Object.assign({
			parseFragmentIdentifier: true,
			[encodeFragmentIdentifier]: false
		}, options);

		const {url, query, fragmentIdentifier} = exports.parseUrl(input, options);
		return exports.stringifyUrl({
			url,
			query: filterObject(query, filter),
			fragmentIdentifier
		}, options);
	};

	exports.exclude = (input, filter, options) => {
		const exclusionFilter = Array.isArray(filter) ? key => !filter.includes(key) : (key, value) => !filter(key, value);

		return exports.pick(input, exclusionFilter, options);
	};
} (queryString));

var _OktaRequest_instances, _OktaRequest_onProcessSuccess, _OktaRequest_onError, _OktaRequest_redirectOkta, _OktaRequest_handleOktaCallback, _OktaRequest_authenticateAndGetToken, _OktaRequest_processJWT, _OktaRequest_validateToken;
class OktaRequest {
    constructor(config) {
        _OktaRequest_instances.add(this);
        this.config = null;
        this.callbackPath = null;
        _OktaRequest_onProcessSuccess.set(this, void 0);
        _OktaRequest_onError.set(this, void 0);
        this.config = config;
        this.okta = oktaModelProxy(new OktaModel());
        this.callbackPath = new URL(this.config.oidc.redirectUri).pathname;
    }
    set onProcessSuccess(value) {
        __classPrivateFieldSet(this, _OktaRequest_onProcessSuccess, value, "f");
    }
    set onError(value) {
        __classPrivateFieldSet(this, _OktaRequest_onError, value, "f");
    }
    authenticate() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.okta.isAuthenticated)
                return;
            if (location.pathname === this.callbackPath) {
                __classPrivateFieldGet(this, _OktaRequest_instances, "m", _OktaRequest_handleOktaCallback).call(this);
            }
            else {
                __classPrivateFieldGet(this, _OktaRequest_instances, "m", _OktaRequest_redirectOkta).call(this);
            }
        });
    }
    unauthorizedHandler() {
        this.okta.idToken = null;
        this.okta.accessToken = null;
        this.okta.tokenData = null;
        this.okta.userData = {};
        this.okta.isAuthenticated = null;
        this.authenticate();
    }
}
_OktaRequest_onProcessSuccess = new WeakMap(), _OktaRequest_onError = new WeakMap(), _OktaRequest_instances = new WeakSet(), _OktaRequest_redirectOkta = function _OktaRequest_redirectOkta() {
    return __awaiter(this, void 0, void 0, function* () {
        const { oidc } = this.config;
        // Create and store a random "state" value
        var state = generateRandomString();
        localStorage.setItem('pkce_state', state);
        // Create and store a new PKCE code_verifier (the plaintext random secret)
        var code_verifier = generateRandomString();
        localStorage.setItem('pkce_code_verifier', code_verifier);
        var code_challenge = yield pkceChallengeFromVerifier(code_verifier);
        if (location.href.includes(this.callbackPath))
            localStorage.setItem('redirectBack', location.origin + '/');
        else
            localStorage.setItem('redirectBack', location.href);
        // Build the authorization URL
        var url = `${oidc.issuer}/v1/authorize` +
            '?response_type=code' +
            '&client_id=' +
            encodeURIComponent(oidc.clientId) +
            '&state=' +
            encodeURIComponent(state) +
            '&scope=' +
            encodeURIComponent(['openid', 'profile', 'email'].join(' ')) +
            '&redirect_uri=' +
            encodeURIComponent(oidc.redirectUri) +
            '&code_challenge=' +
            encodeURIComponent(code_challenge) +
            '&code_challenge_method=S256';
        // Redirect to the authorization server
        window.location.href = url;
    });
}, _OktaRequest_handleOktaCallback = function _OktaRequest_handleOktaCallback() {
    return __awaiter(this, void 0, void 0, function* () {
        const { code, state, error, error_description } = queryString.parse(location.search);
        const { oidc } = this.config;
        console.log('handle authentication callback');
        try {
            if (code && !error && localStorage.getItem('pkce_state') === state) {
                var url = `${oidc.issuer}/v1/token`;
                const body = yield __classPrivateFieldGet(this, _OktaRequest_instances, "m", _OktaRequest_authenticateAndGetToken).call(this, url, {
                    grant_type: 'authorization_code',
                    code,
                    client_id: oidc.clientId,
                    redirect_uri: oidc.redirectUri,
                    code_verifier: localStorage.getItem('pkce_code_verifier'),
                });
                console.log(`access token received!`);
                this.okta.idToken = body.id_token;
                this.okta.accessToken = body.access_token;
                __classPrivateFieldGet(this, _OktaRequest_instances, "m", _OktaRequest_processJWT).call(this, this.okta.accessToken);
            }
            else if (error === 'not_assigned') {
                this.okta.authenticationError = AUTHENTICATION_ERRORS.NOT_ASSIGNED;
                if (__classPrivateFieldGet(this, _OktaRequest_onError, "f"))
                    __classPrivateFieldGet(this, _OktaRequest_onError, "f").call(this, this.okta.authenticationError);
            }
            else {
                this.okta.authenticationError = error || AUTHENTICATION_ERRORS.ERROR;
                if (__classPrivateFieldGet(this, _OktaRequest_onError, "f"))
                    __classPrivateFieldGet(this, _OktaRequest_onError, "f").call(this, this.okta.authenticationError);
                console.error(`Authentication error: ${error}: ${error_description}`);
            }
        }
        catch (error) {
            this.okta.authenticationError = AUTHENTICATION_ERRORS.NOT_ASSIGNED;
            if (__classPrivateFieldGet(this, _OktaRequest_onError, "f"))
                __classPrivateFieldGet(this, _OktaRequest_onError, "f").call(this, this.okta.authenticationError);
        }
        finally {
            localStorage.removeItem('pkce_state');
        }
    });
}, _OktaRequest_authenticateAndGetToken = function _OktaRequest_authenticateAndGetToken(url, body) {
    return __awaiter(this, void 0, void 0, function* () {
        return request(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            },
            body: Object.keys(body)
                .map(key => key + '=' + body[key])
                .join('&'),
        }, this.unauthorizedHandler);
    });
}, _OktaRequest_processJWT = function _OktaRequest_processJWT(token) {
    try {
        console.info(`processing jwt`);
        this.okta.tokenData = parseToken(token);
        if (!__classPrivateFieldGet(this, _OktaRequest_instances, "m", _OktaRequest_validateToken).call(this)) {
            this.authenticate();
            return;
        }
        this.okta.userData = extractUserData(this.okta.tokenData);
        let uniqueOrganizations = getUniqueOrganizations(this.okta.userData);
        let defaultOrganizationId = this.okta.userData.organization;
        if (!defaultOrganizationId && this.okta.userData.email.includes('au10tix.com')) {
            defaultOrganizationId = 326;
        }
        else {
            defaultOrganizationId = uniqueOrganizations[0].split('.')[1];
        }
        const groups = this.okta.userData.groups;
        this.okta.clientOrganizations = uniqueOrganizations.reduce((clientOrganizations, clientOrganization) => {
            let [name, id] = clientOrganization.split('.');
            clientOrganizations[id] = {
                id,
                name,
                isOrgManager: groups.includes(`${name}.${id}.cm.manager`),
                isReadOnlyOrgManager: groups.includes(`${name}.${id}.cm.readonlymanager`),
                isAdmin: groups.includes(`${name}.${id}.cm.admin`),
                isAu10tixConfigOnlyAdmin: groups.includes(`${name}.${id}.cm.au10tix-admin`),
                isConsoleUser: groups.includes(`${name}.${id}.cm`),
            };
            return clientOrganizations;
        }, {});
        this.okta.clientOrganization = this.okta.clientOrganizations[defaultOrganizationId];
        this.okta.isAu10tixAdmin = groups.includes(`au10tix-admin.${this.config.env}`);
        this.okta.isAuthenticated = true;
        if (__classPrivateFieldGet(this, _OktaRequest_onProcessSuccess, "f"))
            __classPrivateFieldGet(this, _OktaRequest_onProcessSuccess, "f").call(this, this.okta);
    }
    catch (ex) {
        this.okta.authenticationError = AUTHENTICATION_ERRORS.JWT_PARSING_ERROR;
        console.error(`Error processing JWT: ${ex}`);
        this.okta.isAuthenticated = false;
        if (__classPrivateFieldGet(this, _OktaRequest_onError, "f"))
            __classPrivateFieldGet(this, _OktaRequest_onError, "f").call(this, this.okta.authenticationError);
    }
}, _OktaRequest_validateToken = function _OktaRequest_validateToken() {
    if (this.okta.tokenData.exp * 1000 < Date.now())
        return false;
    return true;
};
window.oktaAuth = {OktaConfig, OktaRequest};
