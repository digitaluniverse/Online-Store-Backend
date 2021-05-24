
# ProShop API
Backend for Proshop Project

# Prerequisites
Create Virtual Enviornment

Install Required Packages
```
pip3 install -r requirements.txt
```
Create a local .env with enviornment variables
```
DJANGO_SECRET_KEY=django_secret_key_here
```

# Getting Started 
To make preparations for running the REST API locally on your machine go ahead and launch a terminal and proceed to using the following commmands in order 

```
python3 manage.py makemigrations
```
```
python3 manage.py migrate
```
### Create Superuser (for adding dummy data to the api's core for testing)
```
python3 manage.py createsuperuser
```
* Fill in the required info to create your superuser
* Make sure not to skip any fields to avoid errors

# Launch
To finally launch the API on your local server after completing the above just run the following command 
```
python3 manage.py runserver 
```

For visiting the admin panel, simply visit the following **URL** and login with the superuser account you created earlier.

[http://localhost/admin](http://localhost/admin)

## Add an oauth2 application from the admin

[http://localhost:8000/admin/oauth2_provider/application/add/](http://localhost:8000/admin/oauth2_provider/application/add/)

**User: choose an admin user created in the previous step**

**Client type: Confidential**

**Authorization grant-type: Resource owner password based**

**Name: choose any name**

![enter image description here](https://raw.githubusercontent.com/digitaluniverse/readme-resources/main/proshop-backend/oauthSetup.png)
