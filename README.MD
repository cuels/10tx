# AU10TIX Integration Tool

## Overview

The AU10TIX Integration Tool enables you to setup the API integration for
AU10TIX using a few commands on the Command Line Interface (CLI). 

The tool enables the following:

* Authentication
* API Integration
* Sample Codes

## Prerequisites

* [Node JS](https://nodejs.org/en/download/) version `16.20.1`.
* Command Line Interface

* Environment:
  * `staging`
  * `production`

* Region from AU10TIX Support:
  * **`eus`**
  * **`weu`**
  * **`ejp`**
  * **`wus`**

## Workflow

1. Download and extract the contents of `10tx.zip`.
2. Unzip the 10tx directory and it's contents in your projects directory.
3. Open the CLI and run:
   1. `npm install`
   2. `npm link`
   3. `10tx set-config env={env} region={region}`
      * Replace `{env}` with the environment you are using, either `staging` or `production`.
      * Replace `{region}` with the region AU10TIX Support provides for your base URL.
   4. `10tx setup`
4. Navigate to `/sample-code/auth.js` and `/sample-code/webApp` for editable sample code.   

## File Structure

```bash
cli
node_modules
sample-code
          |
          webApp
                |
                index.js 
          auth.js
          index.js
urls.js
```

* **`cli`**: Contains the 'internal' code for the CLI tool.
* **`node_modules`**: Node JS dependencies to the cli tool.
* **`sample-code`**: Sample code for:
  * `auth.js`: Authentication
  *  `/webApp/index.js`: Workflow `Au10tix201`, AU10TIX Web App + ID Verification.
* **`urls.js`**: Small utility to determine the API url.

## Getting Started

### Installing the tool

Run the following from the CLI in the 10tx root folder:

`npm install`
`npm link`

### Configure the environment (`env`) and region (`region`)

`10tx set-config env={env} region={region}`

AU10TIX Support sends you the region which is required to determine API baseline URL.
The regions are as follows:

* **`eus`**
* **`weu`**
* **`ejp`**
* **`wus`**

Select the environment to run in:

* **`staging`**
* **`production`** 

Example:
`10tx set-config env=staging region=eus`

### Run the Setup tool

Run the following from the CLI in the 10tx root folder:

`10tx setup`

The `setup` command runs the following steps:

1. Setup and Provisioning (needs to be done only once):
   1. Generates a Private-Public Key pair. The Private amd Public key files are
      saved in the `./keys` folder.
      {{% note %}}
      If `10tx setup`is run after the first time, you must assign a new `keyid`for the Public Key as follows:
      `10tx setup --keyid=key2`
      {{% /note %}} 
   2. Login opens to AU10TIX service to upload the Public Key to AU10TIX. 
      You are required to enter your Username and Password (given by AU10TIX Support).
      On completion close the browser window, and return to the CLI.
   
    
2. Run the Sample Code (API call).
   1. Creates a JWT (JSON Web Token) signed with the Private Key generated in step 1.1.
   2. Call AU10TIX Authentication API to acquire an Access Token.
   3. Call AU10TIX workflow `Au10tix201`, AU10TIX Web App + ID Verification, 
      with the acquired Access Token.
   4. Open a browser with the Web App link.   

{{% note %}}
Use `10tx --help` command for more commands and options.
{{% /note %}}

## Next Steps

### Configuring the Sample Code

The Sample Code provided is for workflow `Au10tix201`, AU10TIX Web App + ID Verification.
See [Web App](/getting-started/integrations/web-app/) for more details.

```js
33 const { env, region } = getConfig();
34     const url = `${urls[env].apiUrl(region)}/workflow/v1/workflows/person/Au10tix201`;
35     console.log(`2. Calling AU10TIX to create a webapp link: ${url}`);
36     const body = {
37         serviceOptions: {
38             secureme: {
39                 requestTypes: {
40                     idFront: ['camera', 'file'],
41                     idBack: ['camera', 'file'],
42                     faceCompare: ['camera', 'file']
43                 }
44             }
45         }
46     }
```

To configure the Sample Code for other workflows, edit the `url` and `serviceOptions` of
`./sample-code/webApp/index.js` as follows:

#### `url`

`34    const url = `${urls[env].apiUrl(region)}/workflow/v1/workflows/person/Au10tix201

Replace `Au10tix201` with the workflow ID supplied by AU10TIX Support.

Example:

For AU10TIX ID Verification flow replace `Au10tix201` with `Au10tix101`.

`34     const url = `${urls[env].apiUrl(region)}/workflow/v1/workflows/person/Au10tix101`;`

#### `serviceOptions`

Replace `serviceOptions` with the parameters corresponding to the new service.
See [`startWorkflow`>REQUEST BODY SCHEMA:>`serviceOptions` ](/api/orchestrator/#tag/workflows/operation/startWorkflow)

Example:

For AU10TIX ID Verification flow replace `serviceOptions` as follows:

```js
37         serviceOptions: {
38             media:[`idFront`, `idBack`],
39             idv:{
40                enableComparison:true
41             }
43          }
```