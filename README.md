# TIPro

This project is a tool for fetching, analyzing, and reporting data from various CTI (Cyber Threat Intelligence) sources. The project is containerized using Docker and interacts with different CTI sources (VirusTotal, OTX, Shodan, etc.).

## Installation

### Requirements

- Docker
- Docker Compose (optional)

### Running With Docker
### Step 1: Clone the Project

```sh
git clone https://github.com/0xK3rn3lP4n1c/TIPro
cd TIPro
```

Build the Docker image using the following command:

```sh
docker build -t your_project_name -f docker/Dockerfile .
```

Set the necessary API keys for the project to work. The following command will run the Docker container with the required environment variables:

```sh
docker run -d --name your_project_container -e OTX_API_KEY=your_otx_key -e VT_API_KEY=your_vt_key your_project_name
```

If you prefer to store environment variables in a .env file, create a .env file in the project root directory:

.env

    OTX_API_KEY=your_otx_key
    VT_API_KEY=your_vt_key
    ABUSEIPDB_API_KEY=your_abuseipdb_api_key
    GREYNOISE_API_KEY=your_greynoise_api_key
    SHODAN_API_KEY=your_shodan_api_key

Start the Docker container to run the project:

```sh
docker run -d --name your_project_container your_project_name
```


## Running the Project Locally

If you prefer to run the project locally, follow these steps:

    Install the requirements:

```sh
pip install -r requirements.txt
```
Set the environment variables:

```sh
export OTX_API_KEY=your_otx_key
export VT_API_KEY=your_vt_key
```
Run the project:

```sh
python3 main.py
```