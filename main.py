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
    print("¡Conexión exitosa a MongoDB Atlas!")
except Exception as e:
    print(f"Error al conectar a MongoDB Atlas: {e}")


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
    # Buscamos si el producto existe antes de intentar cambiarlo
    producto_existente = productos_col.find_one({"_id": producto_id})
    if not producto_existente:
        raise HTTPException(status_code=404, detail="El producto no existe en la tiendita.")
    
    # Convertimos los datos que mandó Android a un diccionario compatible con Mongo
    datos_dict = datos_actualizados.dict(by_alias=True, exclude={"id"})
    
    # Preservamos la fecha de creación original para que no se borre
    datos_dict["fecha_creacion"] = producto_existente.get("fecha_creacion", datetime.utcnow().strftime("%Y-%m-%d"))
    
    # Inyectamos los nuevos metadatos de actualización
    datos_dict["fecha_actualizacion"] = datetime.utcnow().strftime("%Y-%m-%d")
    datos_dict["creado_por"] = producto_existente.get("creado_por", "AppAndroid") # Mantiene quién lo creó originalmente
    
    # Hacemos el reemplazo en MongoDB
    resultado = productos_col.update_one(
        {"_id": producto_id},
        {"$set": datos_dict}
    )
    
    return {"status": "success", "message": f"Producto '{datos_actualizados.nombre}' actualizado correctamente por el Encargado."}


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


@app.delete("/productos/{producto_id}", tags=["Productos"])
def eliminar_producto(producto_id: str, token_data: dict = Depends(verificar_permiso_encargado)):
    resultado = productos_col.update_one({"_id": producto_id}, {"$set": {"activo": False}})
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    return {"status": "success", "message": "Producto dado de baja exitosamente."}