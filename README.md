# VulnCheck
API scripts pertaining to VulnCheck

## Background

Requirements (Global)

- Python 3.11+
- pipenv - https://pypi.org/project/pipenv/

## VulnCheck Community API Docs

- https://docs.vulncheck.com/api 

## Configuration Explained

- There is a sample environment variables file called *.env_sample* under the root folder of this project
- Clone this file and create one called *.env* where you input all of your secrets (API Keys + Access Key Pairs)
- Parameters - explanations of what you see in *.env_sample*

`VULNCHECK_API_KEY` - Community API key

`SAVE_PATH` - Default path to save script file output

## Getting Started

- Clone this repository

```
git clone https://github.com/TechnoSavage/VulnCheck.git
```

- Clone .env_sample to .env under the same directory

```
cp .env_sample .env
```

- Update all of the secrets in the *.env* needed based on the script you'd like to run (NOTE: you need to rerun *pipenv shell* anytime you update these values to reload them)

- Install dependancies

```
pipenv install -r requirements.txt
```

- Enter pipenv

```
pipenv shell
```
