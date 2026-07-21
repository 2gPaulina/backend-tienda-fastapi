import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, status, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient

# 1. INSTANCIAR FASTAPI
app = FastAPI(
    title="API de Punto de Venta e Inventario",
    description="Backend de servicios para la administración de usuarios y productos con JWT",
    version="1.0"
)

# Configuración de seguridad para JWT
JWT_SECRET = "super_secret_key_12345"
JWT_ALGORITHM = "HS256"

# 2. CONEXIÓN A MONGODB ATLAS
MONGO_URI = "mongodb+srv://paulinagarcia_db_user:ORH5JJkOLEmbdjPn@cluster0.j5bk6c4.mongodb.net/?appName=Cluster0"

try:
    client = MongoClient(MONGO_URI)
    db = client["puntoventaGCP"]  
    usuarios_col = db["usuarios"]
    productos_col = db["productos"]
    categorias_col = db["categorias"]
    marcas_col = db["marcas"]
    historial_precios_col = db["historial_precios"]  # Nueva colección para auditoría de precios
    tickets_col = db["tickets"]
    print("¡Conexión exitosa a MongoDB Atlas!")
except Exception as e:
    print(f"Error al conectar a MongoDB Atlas: {e}")

class CategoriaSchema(BaseModel):
    nombre: str = Field(..., description="Nombre de la categoría, ej: Abarrotes")
    descripcion: Optional[str] = Field(None, description="Descripción opcional")

class MarcaSchema(BaseModel):
    nombre: str = Field(..., description="Nombre de la marca, ej: Coca-Cola")
    origen: Optional[str] = Field(None, description="Origen de la marca opcional")

# 3. MODELOS DE VALIDACIÓN DE DATOS (PYDANTIC)
class LoginRequest(BaseModel):
    firebase_token: str
    correo: str

class ProveedorSchema(BaseModel):
    nombre: str
    direccion: str

class ProductoSchema(BaseModel):
    id: str = Field(..., alias="_id", description="Código de barras")
    nombre: str
    descripcion: str
    precio_compra: float
    precio_venta: float
    inventario: int
    categoria_nombre: str
    marca_nombre: str
    proveedor: ProveedorSchema
    creado_por: Optional[str] = ""
    activo: bool = True

class HistorialPrecioSchema(BaseModel):
    producto_id: str
    nombre_producto: str
    precio_compra_anterior: float
    precio_compra_nuevo: float
    precio_venta_anterior: float
    precio_venta_nuevo: float
    fecha_cambio: str
    modificado_por: str

# 4. FUNCIONES AUXILIARES PARA JWT Y CONTROL DE ACCESO
def crear_access_token(data: dict, expires_delta: timedelta = timedelta(hours=2)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Función de seguridad para validar el rol directamente desde el encabezado Authorization
def verificar_permiso_encargado(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    try:
        # Quitamos el prefijo 'Bearer ' que manda Android
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Validación estricta del rol guardado en la base de datos
        if payload.get("rol") != "Encargado":
            raise HTTPException(status_code=403, detail="No tienes permisos (Requiere Encargado)")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


# 5. ENDPOINT: PANTALLA DE TEST
@app.get("/", tags=["Test"])
def pantalla_de_test():
    return {
        "status": "success",
        "code": status.HTTP_200_OK,
        "message": "El backend de servicios (FastAPI) está funcionando correctamente.",
        "database_connected": "puntoventaGCP @ MongoDB Atlas",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


# 6. ENDPOINT: INICIO DE SESIÓN CON JWT (CORREGIDA RUTA PARA ANDROID)
##@app.post("/login", tags=["Autenticación"])
@app.post("/auth/login", tags=["Autenticación"])
def login_usuario(login_data: LoginRequest):
    usuario_db = usuarios_col.find_one({"correo": login_data.correo})
    
    if not usuario_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El usuario no se encuentra registrado en la base de datos de la tienda."
        )
        
    payload = {
        "firebase_uid": usuario_db.get("firebase_uid"),
        "nombre": usuario_db.get("nombre"),
        "correo": usuario_db.get("correo"),
        "rol": usuario_db.get("rol")  
    }
    
    token_jwt = crear_access_token(data=payload)
    return {
        "status": "authenticated",
        "token_jwt": token_jwt,
        "usuario": {
            "nombre": payload["nombre"],
            "rol": payload["rol"]
        }
    }


# 7. MÓDULO DE PRODUCTOS (CORREGIDAS RUTAS SIN '/' AL FINAL PARA EVITAR REDIRECTS 307)

@app.post("/productos", tags=["Productos"], status_code=status.HTTP_201_CREATED)
def crear_producto(producto: ProductoSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    existe = productos_col.find_one({"_id": producto.id})
    if existe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El producto con código {producto.id} ya existe."
        )
    nuevo_prod = producto.dict(by_alias=True)
    
    # Inyectamos metadatos del sistema
    nuevo_prod["fecha_creacion"] = datetime.utcnow().strftime("%Y-%m-%d")
    nuevo_prod["fecha_actualizacion"] = datetime.utcnow().strftime("%Y-%m-%d")
    nuevo_prod["creado_por"] = token_data.get("nombre", "AppAndroid")
    
    productos_col.insert_one(nuevo_prod)
    return {"status": "success", "message": f"Producto '{producto.nombre}' registrado con éxito por Encargado."}


@app.get("/productos", tags=["Productos"], response_model=List[ProductoSchema])
def listar_productos():
    cursor = productos_col.find({"activo": True})
    return [doc for doc in cursor]


@app.get("/productos/{producto_id}", tags=["Productos"], response_model=ProductoSchema)
def obtener_producto_por_id(producto_id: str):
    producto = productos_col.find_one({"_id": producto_id, "activo": True})
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    return producto


@app.put("/productos/{producto_id}", tags=["Productos"])
def actualizar_producto(producto_id: str, datos_actualizados: ProductoSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    # 1. Buscar si el producto existe antes de intentar cambiarlo
    producto_existente = productos_col.find_one({"_id": producto_id})
    if not producto_existente:
        raise HTTPException(status_code=404, detail="El producto no existe en la tiendita.")
    
    # 2. Detectar si hubo un cambio en los precios (Compra o Venta)
    precio_compra_viejo = float(producto_existente.get("precio_compra", 0.0))
    precio_venta_viejo = float(producto_existente.get("precio_venta", 0.0))
    
    cambio_compra = precio_compra_viejo != datos_actualizados.precio_compra
    cambio_venta = precio_venta_viejo != datos_actualizados.precio_venta
    
    # 3. Si hubo cambios, guardamos el registro de auditoría en la nueva colección
    if cambio_compra or cambio_venta:
        log_precio = {
            "producto_id": producto_id,
            "nombre_producto": producto_existente.get("nombre", "Desconocido"),
            "precio_compra_anterior": precio_compra_viejo,
            "precio_compra_nuevo": datos_actualizados.precio_compra,
            "precio_venta_anterior": precio_venta_viejo,
            "precio_venta_nuevo": datos_actualizados.precio_venta,
            "fecha_cambio": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "modificado_por": token_data.get("nombre", "Encargado Anonimo")
        }
        historial_precios_col.insert_one(log_precio)
    
    # 4. Procesar la actualización normal del producto
    datos_dict = datos_actualizados.dict(by_alias=True, exclude={"id"})
    
    # Preservar metadatos originales
    datos_dict["fecha_creacion"] = producto_existente.get("fecha_creacion", datetime.utcnow().strftime("%Y-%m-%d"))
    datos_dict["fecha_actualizacion"] = datetime.utcnow().strftime("%Y-%m-%d")
    datos_dict["creado_por"] = producto_existente.get("creado_por", "AppAndroid")
    
    # Reemplazo en MongoDB
    productos_col.update_one(
        {"_id": producto_id},
        {"$set": datos_dict}
    )
    
    return {
        "status": "success", 
        "message": f"Producto '{datos_actualizados.nombre}' actualizado correctamente. Auditoría de precios registrada."
    }

@app.get("/productos/{producto_id}/historial-precios", tags=["Productos"])
def obtener_historial_precios(producto_id: str, token_data: dict = Depends(verificar_permiso_encargado)):
    cursor = historial_precios_col.find({"producto_id": producto_id}, {"_id": 0})
    historial = [doc for doc in cursor]
    return {
        "producto_id": producto_id,
        "total_actualizaciones": len(historial),
        "historial": historial
    }

# Ruta de venta modificada para coincidir con Android 'ventas' (R3)
@app.post("/ventas", tags=["Productos"])
def realizar_venta_producto(venta_req: dict):
    producto_id = venta_req.get("codigo_barras")
    cantidad = venta_req.get("cantidad", 1)
    
    producto = productos_col.find_one({"_id": producto_id})
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    
    inventario_actual = producto.get("inventario", 0)
    if inventario_actual < cantidad:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Solo quedan {inventario_actual} unidades disponibles."
        )
    
    productos_col.update_one(
        {"_id": producto_id},
        {"$inc": {"inventario": -cantidad}}
    )
    
    return {
        "status": "sold",
        "inventario_nuevo": inventario_actual - cantidad
    }

@app.post("/categorias", tags=["Categorías"], status_code=status.HTTP_201_CREATED)
def crear_categoria(categoria: CategoriaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    # Buscamos si ya existe para no duplicar por nombre
    existe = categorias_col.find_one({"nombre": categoria.nombre})
    if existe:
        raise HTTPException(status_code=400, detail=f"La categoría '{categoria.nombre}' ya existe.")
    
    nueva_cat = categoria.dict()
    categorias_col.insert_one(nueva_cat)
    return {"status": "success", "message": f"Categoría '{categoria.nombre}' registrada correctamente."}

@app.get("/categorias", tags=["Categorías"])
def listar_categorias():
    # Retorna todas las categorías registradas (quitando el _id de Mongo para evitar errores de JSON)
    cursor = categorias_col.find()
    return [{"nombre": doc["nombre"], "descripcion": doc.get("descripcion", "")} for doc in cursor]


# --- ENDPOINTS DE MARCAS ---
@app.post("/marcas", tags=["Marcas"], status_code=status.HTTP_201_CREATED)
def crear_marca(marca: MarcaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    existe = marcas_col.find_one({"nombre": marca.nombre})
    if existe:
        raise HTTPException(status_code=400, detail=f"La marca '{marca.nombre}' ya existe.")
    
    nueva_marca = marca.dict()
    marcas_col.insert_one(nueva_marca)
    return {"status": "success", "message": f"Marca '{marca.nombre}' registrada correctamente."}

@app.get("/marcas", tags=["Marcas"])
def listar_marcas():
    cursor = marcas_col.find()
    return [{"nombre": doc["nombre"], "origen": doc.get("origen", "")} for doc in cursor]


@app.delete("/productos/{producto_id}", tags=["Productos"])
def eliminar_producto(producto_id: str, token_data: dict = Depends(verificar_permiso_encargado)):
    resultado = productos_col.update_one({"_id": producto_id}, {"$set": {"activo": False}})
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    return {"status": "success", "message": "Producto dado de baja exitosamente."}

# --- ELIMINAR CATEGORÍAS ---
@app.delete("/categorias/{nombre}", tags=["Categorías"])
def eliminar_categoria(nombre: str, token_data: dict = Depends(verificar_permiso_encargado)):
    # Eliminación física en MongoDB
    resultado = categorias_col.delete_one({"nombre": nombre})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="La categoría no existe.")
    return {"status": "success", "message": f"Categoría '{nombre}' eliminada correctamente."}

# --- ELIMINAR MARCAS ---
@app.delete("/marcas/{nombre}", tags=["Marcas"])
def eliminar_marca(nombre: str, token_data: dict = Depends(verificar_permiso_encargado)):
    # Eliminación física en MongoDB
    resultado = marcas_col.delete_one({"nombre": nombre})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="La marca no existe.")
    return {"status": "success", "message": f"Marca '{nombre}' eliminada correctamente."}