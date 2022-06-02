from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
app = Flask(__name__)#Se crea una intancia de la clase con el nombre de la aplicacion en ejecución

#---------------Para poder usar la DB---------------------
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup_2 import Restaurant, Base, MenuItem, User
engine = create_engine('sqlite:///restaurant_menu_with_users.db', connect_args = {"check_same_thread": False})
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()
#--------------------------------------------------------------

#Step 2 Create anti-forgery state token:
from flask import session as login_session
import random, string
#-----------------------------------------

#Step 5 Google Connect:
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
#import httplib2#Se puede usar requests para lo que le toca hacer a esta clase.
import json
from flask import make_response
import requests
#Extraer el secreto del cliente del JSON:
CLIENT_ID = json.loads(open('client_screts.json', "r").read())['web']['client_id']
#----------------------------------------------------------------------------------

#GitHub Connect:
from flask_dance.contrib.github import make_github_blueprint, github
import os

#Info de la App creada en GitHub:
client_id = "54d692335ea1f4faac1a"
client_secrets = "9fca7cb612310ba0796f0e0d1ef7ecec396d7808"

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'#Para evitar que se bloquee por no ser https.
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'#Permite ampliar el scope a la hora de hacer requests.
gbp = make_github_blueprint(client_id = client_id, client_secret = client_secrets, scope = "email")
app.register_blueprint(gbp, url_prefix = '/github_login')

#---------------------------------------------------------


#Esta funcion se ejecutara cuando se esté en una de estas rutas.
@app.route("/")
@app.route("/restaurants")
def show_restaurants():
	"""
	Esta funcion mostrara todos los restaurantes disponibles, dará la opcion de crear, borar y editar, y ademas permitira acceder al menu de cada uno.	
	"""

	#Para sacar la info de GitHub:
	if login_session.get('provider') == "GitHub":
		get_github_info()
		add_to_DB_or_not()
		
	rests = session.query(Restaurant).all()

	return render_template("show_restaurants.html", rests = rests, lg = login_session)


@app.route("/restaurants/new_rest", methods = ["GET", "POST"])
def new_rest():

	#En caso de que se intente acceder a esta dirección sin haber iniciado sesión
	if len(login_session) == 0:
		flash("Debe iniciar seción para poder crear nuevos restaurantes")
		return redirect(url_for("show_restaurants"))

	if request.method == "GET":
		return render_template("new_rest.html")

	if request.method == "POST":
		nombre = request.form['name']
		
		if nombre == "":
			nombre = "Unamed New Restaurant"

		new_rest = Restaurant(name = nombre, user_id = login_session['user_id'])#Ojo: no se espefisica el id porque este será creado automaticamente.
		session.add(new_rest)
		session.commit()
		flash("Un nuevo restaurante ha sido crado, su nombre es: '{}'.".format(nombre))
		return redirect(url_for('show_restaurants'))



@app.route("/restaurants/<int:restaurant_id>/edit", methods = ['GET', 'POST'])
def edit_rest(restaurant_id):
	"""
	Permite editar un restaurante, pero solo al administrador o a el creador de este. 
	"""

	restaurant = session.query(Restaurant).get(restaurant_id)

	#En caso de que se intente acceder a esta dirección sin haber iniciado sesión
	if len(login_session) == 0 or login_session.get('user_id') != restaurant.user_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder editar el restaurante: '{}'.".format(restaurant.name))
		return redirect(url_for("show_restaurants"))

	if request.method == "GET":
		return render_template("edit_rest.html", rest = restaurant)#"rest" es la variable a la cual podré acceder en "edit_rest.html"

	if request.method == "POST":
		nuevo_nombre = request.form['name']
		
		if nuevo_nombre == "":
			nuevo_nombre = restaurant.name

		viejo_nombre = restaurant.name
		restaurant.name = nuevo_nombre
		session.add(restaurant)#Agregar el rest con el nombre actualizado.
		session.commit()
		flash("El nombre de '{}' a sido cambiado a '{}' ".format(viejo_nombre, nuevo_nombre))
		return redirect(url_for('show_restaurants'))

@app.route("/restaurants/<int:restaurant_id>/delete", methods = ['GET', 'POST'])
def delete_rest(restaurant_id):
	"""
	Borra el restarurante seleccionado y todos los items de su menú.
	"""
	restaurant = session.query(Restaurant).get(restaurant_id)
	
	#En caso de que se intente acceder a esta dirección sin haber iniciado sesión
	if len(login_session) == 0 or login_session.get('user_id') != restaurant.user_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder borrar el restaurante: '{}'.".format(restaurant.name))
		return redirect(url_for("show_restaurants"))
	
	if request.method == "GET":		
		return render_template("delete_rest.html", rest = restaurant)

	if request.method == "POST":
		nombre = restaurant.name
		session.delete(restaurant)
		
		#Borrar los items del menú del restaurante:
		rest_items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id)
		
		for item in rest_items:
			session.delete(item)

		session.commit()

		flash("El restaurante llamado: '{}' ha sido eliminado.".format(nombre))
		return redirect(url_for('show_restaurants'))	

	
@app.route("/restaurants/<int:restaurant_id>/")#Con esta url estoy espesificando que el segundo elemento es un entero que corresponderá a el id de rest.
def restaurant_menu(restaurant_id):#Aqui se está resiviendo como argumento la segunda parte de la url. 
	
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()#Se puede hacer con ".get()""
	items = session.query(MenuItem).filter_by(restaurant_id = restaurant.id)#SELECT de los items del menu de el primer rest.
	items = list(items)#Con esto funcionará el "if" que hay en la template.
	
	
	if items == []:
		flash("Este menú está vacío")
	
	owner_name = session.query(User).filter_by(id = restaurant.user_id).one().name

	is_allowed = login_session.get('user_id') == 1 or login_session.get('user_id') == restaurant.user_id#Para evitar tener que hacer esta comparación en el frontend. 

	return render_template("menu.html", restaurant = restaurant, items = items, is_allowed = is_allowed, owner_name = owner_name)
	

def show_as_money(num):
	
	"""
	Muestra una cantidad numerica en formato de dinero.
	"""
	if num == "No price given":
		return num

	#En caso de que se reciba el dato desde la funcion edit_rest.
	if num[0] == "$":
		num = float(num[1:])
	else:
		num = float(num)	

	if num < 0:
		num = -num

	num = str(num)

	if num.split(".")[1] == "0":
		num += "0"

	return "$" + num


@app.route("/restaurants/<int:restaurant_id>/new", methods = ['GET', 'POST'])
def new_menu_item(restaurant_id):
	"""
	Este metodo permite crear un nuevo item dentro del menú del restaurante al que corresponde el id que recibe como argumento.
	"""

	#Obtener el id del propietario del restaurante para compararlo con el del user actual.
	restaurant = session.query(Restaurant).get(restaurant_id)
	owner_id = restaurant.user_id

	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder crear nuevos items en el menú de: '{}'.".format(restaurant.name))
		return redirect(url_for("show_restaurants"))
	
	if request.method == 'POST':#Esta condicional se activara al clickar el boton "Crear"

		request.form = dict(request.form)

		if not('course' in request.form):
			request.form['course'] = ""#Esto es porque si no se selecciona ningun radio button la llave 'course' no estará en el dict.
		
		#Todo esto en caso de que el usuario deje algun campo de la forma sin llenar (uno, varios o todos).

		empty_request = {'name': '', 'description': '\t\t\t\t', 'price': '', 'course': ''}#Este es el diccionario que retorna cuando no se llena la forma.
						
		for key in ['name', 'description', 'price', 'course']:#De esta manera reduje la cantidad de lineas de codigo.Con list() se optienen la llaves de todo el dict.
			if request.form[key] == empty_request[key]:
				request.form[key] = "No {} given".format(key)	
				
		#-------------------------------------------------------------------------------------------
			
		new_item = MenuItem(
			name = request.form['name'], 
			restaurant_id = restaurant_id,
			description = request.form['description'],
			price = show_as_money(request.form['price']),
			course = request.form['course'],
			user_id = login_session['user_id']						
			)

		session.add(new_item)
		session.commit()
		flash("Un nuevo item de menú ha sido creado!")
		flash("Su nombre es: '{}'".format(new_item.name)) 
		return redirect(url_for('restaurant_menu', restaurant_id = restaurant_id))

	if request.method == 'GET':#Esto se pudo haber hecho con un "else" pero para fines didacticos lo deje como está.
		return render_template('new_menu_item.html', restaurant_id = restaurant_id)	


@app.route("/restaurants/<int:restaurant_id>/<int:menu_id>/edit/", methods = ['GET', 'POST'])
def edit_menu_item(restaurant_id, menu_id):
	"""
	Este metodo permite editar un item especifico de un restaurante que es ubicado en función de los ids del restaurante y el menú.
	"""
	
	restaurant = session.query(Restaurant).get(restaurant_id)
	owner_id = restaurant.user_id

	#En caso de que se intente acceder a esta dirección sin haber iniciado sesión.

	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder editar los items del menú del restaurante: '{}'".format(restaurant.name))
		return redirect(url_for("show_restaurants"))

	def crete_form(query_object):
		"""
		Esta función sirve para crear el diccionario de la forma que le corresponde a la creacion del elemento.
		"""

		form_dictionari = dict()
		form_dictionari['name'] = query_object.name
		form_dictionari['description'] = query_object.description
		form_dictionari['price'] = query_object.price
		form_dictionari['course'] = query_object.course

		return form_dictionari
	
	menu_item = session.query(MenuItem).filter_by(id = menu_id).one()
	old_form = crete_form(menu_item)

	if request.method == 'GET':
		return render_template('edit_menu_item.html', restaurant_id = restaurant_id, menu_id = menu_id, menu_item = menu_item)

	if request.method == 'POST':
		
		new_from = dict(request.form)
		
		#En caso de que algun campo se quede vacio, este se llenará con la info de la form anterior.
		#Y en caso de que la llave no esté, la agregará.
		for key in old_form.keys():

			if not(key in new_from):
				new_from[key] = old_form[key]

			if new_from[key] == "" or new_from[key] == None:
				new_from[key] = old_form[key]
		
		#Ya en este punto, la nueva forma tiene la info que ha sido actualizada y la que no, ha sido tomada de la vieja.
		menu_item.name = new_from['name']
		menu_item.description = new_from['description']
		menu_item.price = show_as_money(new_from['price'])
		menu_item.course = new_from['course']

		session.add(menu_item)#Agregar el item con el nombre actualizado.
		session.commit()
		flash("El item de nombre: '{}', ha sido editado.".format(old_form['name']))
		return redirect(url_for('restaurant_menu', restaurant_id = restaurant_id))


@app.route("/restaurants/<int:restaurant_id>/delete_all", methods = ["GET", "POST"])
def delete_all(restaurant_id):
	"""
	Este metodo permite borrar todos los items del menú de un restaurante sin borrar el restaurente en si.
	"""
	
	#Obtener el restaurante y todos los items que este posee.	
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id = restaurant.id).all()
	items = list(items)#Para poder iterar con un for.
	owner_id = restaurant.user_id

	#En caso de que se intente acceder a esta dirección sin haber iniciado sesión o no siendo el creador del restaurante o el administrador.
	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder borrar todos los items del menú del restaurante: '{}'.".format(restaurant.name))
		return redirect(url_for("show_restaurants"))

	if request.method == "GET":
		return render_template('delete_all.html', rest = restaurant)

	if request.method == "POST":

		for item in items:
			session.delete(item)#Aqui estoy borrando los items uno por uno, pero ha de haber una forma de hacer una forma directa desde SQLAlchemy. 
		
		session.commit()
		flash("Todos los elementos del menú de este restaurante han sido eliminados.")

		return redirect(url_for('restaurant_menu', restaurant_id = restaurant_id))


@app.route("/restaurants/<int:restaurant_id>/<int:menu_id>/delete/", methods = ['GET', 'POST'])
def delete_menu_item(restaurant_id, menu_id):
	"""
	Borra un item espesifico del menú de un restaurante en función de los ids del restaurante y su menú.
	"""
	menu_item = session.query(MenuItem).filter_by(id = menu_id).one()
	owner_id = menu_item.user_id
	rest_name = session.query(Restaurant).get(menu_item.restaurant_id).name

	#En caso de que se intente acceder a esta dirección sin haber iniciado seción o no siendo el creador del restaurante o el administrador.
	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder borrar items del menú del restaurante: '{}'.".format(rest_name))
		return redirect(url_for("show_restaurants"))

	if request.method == "GET":

		return render_template('delete_menu_item.html', item = menu_item, restaurant_id = restaurant_id, menu_id = menu_id)

	if request.method == "POST":

		session.delete(menu_item)
		session.commit()
		flash("El item llamado: '{}' con ID = {} ha sido eliminado".format(menu_item.name, menu_item.id))
		return redirect(url_for('restaurant_menu', restaurant_id = restaurant_id))	

@app.route("/restaurants/JSON")
def restaurants_JSON():
	"""
	Esta funcion retorna la info de todos los restaurantes en formato JSON.
	"""
	
	if len(login_session) == 0:#Cualquiera que inicie seción podrá ver los JSONs de todos los restaurantes.
		flash("Debe iniciar seción para poder ver los JSONs de los restaurantes.")
		return redirect(url_for("show_restaurants"))

	#Convinación de list comprehension, una query, y las funciones jsonify y serialize, para completar la tearea en una sola linea de codigo: 
	return jsonify(Lista_Restaurantes = [r.serialize for r in session.query(Restaurant).all()])


@app.route("/restaurants/<int:restaurant_id>/JSON")
def restaurant_menu_JOSONs(restaurant_id):
	"""
	Esta función retorna los items del menu en formato JSON.
	"""

	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id = restaurant.id).all()
	owner_id = restaurant.user_id

	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("Debe iniciar seción con la cuenta del propietario para poder ver los items del menú del restaurante: '{}' en formato JSON.".format(restaurant.name))
		return redirect(url_for("show_restaurants"))
	
	return jsonify(menu_items = [item.serialize for item in items])
	#Ojo:serialize es un metodo pero se ejecuta como una propiedad porque se agregó con el decorador @property
	#ver database_setup.py


@app.route("/restaurants/<int:restaurant_id>/<int:menu_id>/JSON")
def restaurant_menu_JOSON_one(restaurant_id, menu_id):
	"""
	Esta función retorna el formato JSON de un Item en espesifico.
	"""

	item = session.query(MenuItem).get(menu_id)
	restaurant = session.query(Restaurant).get(restaurant_id)
	owner_id = restaurant.user_id

	if len(login_session) == 0 or login_session.get('user_id') != owner_id and login_session.get('user_id') != 1:
		flash("El item '{}' pertenece al menú del restaurante '{}' y si desea ver su información en formato JSON debe iniciar seción con la cuenta de su propietario.".format(item.name, restaurant.name))
		return redirect(url_for("show_restaurants"))
	
	return jsonify(menu_item = item.serialize)

#Create a state token to prevent request forgery.
#Store it in the session for later validation.
@app.route("/login")
def show_login():
	state_token = ""

	for i in range(32):
		if i % 2 == 0:
			state_token += random.choice(string.ascii_uppercase)
		else:
			state_token += random.choice(string.digits)

	login_session['state'] = state_token
	return render_template('login2.html', STATE = state_token, lg = login_session)


@app.route('/gconnect', methods = ['POST'])
def gconnect():
	"""
	Función que sirve para iniciar seción con la cuenta de Google del usuario aplicando el protocolo OAuth2.
	"""

	#Comparar el state_token que se generó en el lado del servidor con el que viene del lado del cliente.
	if not(request.args['state'] == login_session['state']):
		response = make_response(json.dumps('Invalid State'), 401)#El mesaje y tipo de erro que se mostrará en la web.
		response.headers['Content-Type'] = 'application/json'
		return response

	code = request.data#El codigo que genera la API del Google que cambia en cada acceso.
	#Crear un objeto oauth_flow
	try:
		oauth_flow = flow_from_clientsecrets('client_screts.json', scope = '')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)

	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade de auth code'), 401)		
		return response

	#Obtener el token y creer la url para hacer la request a la API de Google:
	acces_token = json.loads(credentials.to_json())["access_token"]
	url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(acces_token)
	result = json.loads(str(requests.get(url).text))#Sin nesecidad de usar httplib2.

	#Revisar si hay un error en la respuesta:

	if not(result.get('error') == None):
		response = make_response(json.dumps(result['error']), 501)
		response.headers['Content-Type'] = 'application/json'
		return response	

	google_id = json.loads(credentials.to_json())['id_token']['sub']

	#Comparar el token_id que viene de la request a la API con el que se tiene del lado del servidor:
	if result['user_id'] != google_id:
		response = make_response(json.dumps("Token's user ID does not match given user ID"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#Lo mismo con el ID del cliente:
		
	if result["issued_to"] != CLIENT_ID:
		response = make_response(json.dumps("Token's client ID does not match app's"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#Comprovar si el user esta logiado:

	stored_credentials = login_session.get('credentials')
	stored_google_id = login_session.get('google_id')

	if stored_credentials is not None and google_id == stored_google_id:
		response = make_response(json.dumps('Current user is already connected'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response
	
	#En caso de que no se cumpla ninguna de estas condicionales, proceder a almacenar la info del usuario:
	
	#Crear la url para hacer la request:
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': acces_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params = params)

	data = answer.json()#Trae la info en forma de python dict.
	
	#Guardar la info que retornó la API en la variable login_session:	

	login_session['username'] = data['name']
	login_session['picture_url'] = data['picture']
	login_session['email'] = data['email']
	login_session['access_token'] = acces_token
	login_session['google_id'] = google_id
	login_session['provider'] = "Google"
	
	add_to_DB_or_not()

	return redirect(url_for('show_restaurants'))		


@app.route('/gdisconnect')
def gdisconnect():
	"""
	Desconecta el Google User al borrar la info del login_session dict.
	"""

	#Comporvar si hay un usuario logiado.
	if login_session.get('username') == None:
		response = make_response(json.dumps('Current user not connected'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#Hacer una request para deshabilitar el access_token:

	acces_token = login_session.get('access_token')
	url = "https://accounts.google.com/o/oauth2/revoke?token={}".format(acces_token)
	result = requests.get(url)# Sin nesecidad de usar httplib2.
	
	if result.ok:
		#En caso de que la request (petición) sea exitisa. 	 
		for key in list(login_session):
			del login_session[key]
			
		response = make_response(json.dumps('Seccessfully disconnect'), 200)
		response.headers['Content-Type'] = 'application/json'		
		return redirect(url_for("show_restaurants"))
	
	else:
		#En caso de que falle la request:
		response = make_response(json.dumps('Failed to revoke token for given user'), 400)
		response.headers['Content-Type'] = 'application/json'
		return response

def create_user(login_session):
	"""
	Crea un objeto (registro en el contexto de la BD) de tipo User
	en función del usuario que esta logeado.
	"""

	new_user = User(
				name = login_session['username'],
				email = login_session['email'],
				picture_url = login_session['picture_url']					
		)
	
	session.add(new_user)
	session.commit()

	user = session.query(User).filter_by(email = login_session['email']).one()
	
	return user.id	


def get_user_info(user_id):
	"""
	Retorna un objeto de tipo User en base a su id.
	"""

	user = session.query(User).filter_by(id = user_id).one()
	return user


def get_user_id(email):

	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id

	except:	
		return None

def add_to_DB_or_not():
	"""
	Confirma si el usuario está en la BD, sino lo ingresa.
	hice que esto fuera una función para reducir la cantidad de lineas de codigo.
	"""
	cuasi_id = get_user_id(login_session['email'])

	if cuasi_id:
		login_session['user_id'] = cuasi_id

	else:
		create_user(login_session)
		login_session['user_id'] = cuasi_id

	del cuasi_id#Esta info ya está en el login_session y la DB.

	return None	

		
#Metodos extras agregados con fines de comprovación:

@app.route('/see_all_users', methods = ['GET'])
def see_all_users():
	"""
	Para ver todos los usuarios que hay en la Base de Datos
	"""

	all_users = session.query(User).all()

	if len(all_users) == 0:
		return "No hay Nadie Registrado :("

	output = "Estos son todos los usuarios: <br><br>"
		
	for user in all_users:
		output += "ID = {}, Name: {} <br> ".format(user.id, user.name)

	return output	


@app.route('/see_user', methods = ['GET'])
def see_user():
	"""
	Para ver el user que estó logeado actualmente.
	"""

	if not login_session:
		return "No hay ningún usuario logeado"

	return login_session

@app.route('/see_all_items', methods = ['GET'])
def see_all_items():
	"""
	Para ver todos los items que estan actualmente en la DB. 
	"""

	all_items = session.query(MenuItem).all()

	output = "<h2>Estos son todos los items que están en la DB:</h2>"

	for item in all_items:
		output += "<p>-<b>{}</b>, pertenece a <b>{}</b>, es de tipo <b>{}</b> y fue creado por <b>{}</b> </p>".format(item.name, session.query(Restaurant).get(item.restaurant_id).name, item.course, session.query(User).get(item.user_id).name)

	return output	


@app.route("/log_as_goat/<int:password>")
def log_as_goat(password):
	"""
	Sirve para acceder como el administrador de la Web App.
	"""

	if login_session.get('username') == "The Goat" or login_session.get('username') != None:
		return "Actualmente hay alguien logeado."
		
	if password == 27182:
		the_goat = get_user_info(1)
		login_session['username'] = the_goat.name
		login_session['email'] = the_goat.email
		login_session['picture_url'] = the_goat.picture_url
		login_session['user_id'] = the_goat.id
		flash("El adminstrador principal, 'The Goat' está logeado.")

		return redirect(url_for('show_restaurants'))


	else:
		return "Contaseña incorrecta :("


@app.route("/logout_goat")
def logout_goat():
	"""
	Cierra la sesión del administrador de la Web App.
	"""
	#Comprovar si el adminstrador está logeado:
	if login_session.get('username') == "The Goat":
		#Borrar toda la info que hay en el login_session dict:
		for key in list(login_session):
			del login_session[key]

		flash("El adminstrador ha cerrado seción")
		return redirect(url_for("show_restaurants"))


@app.route("/github_login")
def github_login():
	"""
	Login con Github usando la libreria Flask-Dance.
	"""
	
	is_login = True if login_session.get('username') else False#Ver ternary operators.
	
	if not (github.authorized and is_login):
		login_session['provider'] = "GitHub"
		return redirect(url_for('github.login'))

	return "{} is login".format(login_session['username'])

def get_github_info():
	"""
	Hace la request para optener la informacion de GitHub.
	"""
	if github.authorized:
		r = github.get("/user")
		if r.ok:
			data = r.json()
			login_session["picture_url"] = data["avatar_url"]
			
			if data['name'] == None:
				login_session["username"] = data['login']
			else:	
				login_session["username"] = data['name']

			login_session['email'] = data['email']#Este campo será "null" si el user no tiene un email publico en GitHub.

	else:
		return None 

@app.route("/github_logout")
def github_logout():
	"""
	Borrar la info del login_session dict en caso de que el login se haya hecho con GitHub.
	"""
	if login_session.get('provider') == "GitHub":

		for key in list(login_session):
			del login_session[key]

		return redirect(url_for('show_restaurants'))	

	else:
		return None#Si no se ejecuta el "if" la función igual retornará "None", pero esto lo hace mas legible.


if __name__ == "__main__":
	app.secret_key = "super_secret_key"
	app.debug = True#Esto te permite hacer cambios y poder probarlos sin nesecidad de reiniciar el servidor. 
	app.run(host = "0.0.0.0", port = 5000)























