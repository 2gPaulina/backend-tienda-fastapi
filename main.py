import os
import re
import jwt
import unicodedata
from datetime import datetime, timedelta
from typing import Optional, List, Union, Any
from fastapi import FastAPI, status, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# 1. INSTANCIAR FASTAPI
app = FastAPI(
    title="API de Punto de Venta e Inventario",
    description="Backend de servicios para la administración de usuarios, productos, marcas, categorías, proveedores y distribuidores con JWT",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite conexiones desde cualquier origen web
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    proveedores_col = db["proveedores"]        # Colección de Proveedores independientes
    distribuidores_col = db["distribuidores"]  # Colección de Distribuidores independientes
    historial_precios_col = db["historial_precios"]  # Auditoría de precios
    tickets_col = db["tickets"]
    cortes_caja_col = db["cortes_caja"]
    print("¡Conexión exitosa a MongoDB Atlas!")
except Exception as e:
    print(f"Error al conectar a MongoDB Atlas: {e}")

# 3. MODELOS DE VALIDACIÓN DE DATOS (PYDANTIC)
class LoginRequest(BaseModel):
    firebase_token: str
    correo: str

class CategoriaSchema(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    nombre: str = Field(..., description="Nombre de la categoría, ej: Abarrotes")
    descripcion: Optional[str] = Field(None, description="Descripción opcional")

# Esquema para la colección independiente de Proveedores
class ProveedorColeccionSchema(BaseModel):
    nombre: str = Field(..., description="Nombre del proveedor")

# Esquema para la colección independiente de Distribuidores
class DistribuidorSchema(BaseModel):
    nombre: str = Field(..., description="Nombre del distribuidor")

# Esquema de Marca (con referencia a Distribuidor y Proveedor)
class MarcaSchema(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    nombre: str = Field(..., description="Nombre de la marca, ej: Coca-Cola")
    origen: Optional[str] = Field(None, description="Origen de la marca opcional")
    distribuidor: Optional[str] = Field(None, description="Nombre o ID del distribuidor asociado")
    proveedor: Optional[str] = Field(None, description="Nombre o ID del proveedor asociado")

class ProveedorSchema(BaseModel):
    nombre: str
    direccion: Optional[str] = ""

class ProductoSchema(BaseModel):
    id: str = Field(..., alias="_id", description="Código de barras")
    nombre: str
    descripcion: str
    precio_compra: float
    precio_venta: float
    inventario: int
    categoria_nombre: str
    marca_nombre: str
    proveedor: Union[str, ProveedorSchema, dict, None] = "General"
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

# 4. FUNCIONES AUXILIARES PARA JWT, BÚSQUEDA Y CONTROL DE ACCESO
def crear_regex_insensible(texto: str) -> str:
    """Genera una expresión regular insensible a mayúsculas, minúsculas y acentos"""
    texto_normalizado = unicodedata.normalize('NFD', texto)
    texto_sin_acentos = ''.join(c for c in texto_normalizado if unicodedata.category(c) != 'Mn')
    return f"^{re.escape(texto_sin_acentos)}$"

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

# 6. ENDPOINT: INICIO DE SESIÓN CON JWT
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

# -------------------------------------------------------------
# REGISTRAR VENTA
# -------------------------------------------------------------
@app.post("/ventas", tags=["Productos"])
def realizar_venta_producto(venta_req: dict):
    producto_id = venta_req.get("codigo_barras") or venta_req.get("producto_id") or venta_req.get("_id")
    cantidad = int(venta_req.get("cantidad", 1))
    
    vendedor_correo = (
        venta_req.get("correo_vendedor") or 
        venta_req.get("correo") or 
        venta_req.get("vendedor") or 
        "carlos.mendoza@tiendita.com"
    )
    
    producto = productos_col.find_one({"_id": producto_id})
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    
    inventario_actual = producto.get("inventario", 0)
    if inventario_actual < cantidad:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Solo quedan {inventario_actual} unidades disponibles."
        )
    
    # Restar del inventario
    productos_col.update_one(
        {"_id": producto_id},
        {"$inc": {"inventario": -cantidad}}
    )
    
    precio_unitario = float(producto.get("precio_venta", 0.0))
    total_venta = precio_unitario * cantidad
    
    fecha_actual = datetime.utcnow()
    nuevo_ticket = {
        "producto_id": producto_id,
        "nombre_producto": producto.get("nombre", ""),
        "cantidad": cantidad,
        "precio_unitario": precio_unitario,
        "total": total_venta,
        "vendedor_correo": vendedor_correo,
        "tipo": "VENTA",                     # <-- Identifica la transacción
        "procesado_en_corte": False,         # <-- CLAVE: Nace sin cortar
        "fecha_str": fecha_actual.strftime("%Y-%m-%d"),
        "fecha": fecha_actual.strftime("%Y-%m-%d %H:%M:%S")
    }
    tickets_col.insert_one(nuevo_ticket)
    
    return {
        "status": "sold",
        "total": total_venta,
        "inventario_nuevo": inventario_actual - cantidad
    }

# -------------------------------------------------------------
# CORTE DE CAJA (BÚSQUEDA A PRUEBA DE FALLOS)
# -------------------------------------------------------------
@app.get("/caja/corte-automatico", tags=["Corte de Caja"])
def corte_caja_automatico(correo: str):
    usuario_db = usuarios_col.find_one({"correo": correo})
    
    if not usuario_db:
        nombre = "Carlos Mendoza"
        rol = "Empleado"
    else:
        rol = usuario_db.get("rol", "Cajero")
        nombre = usuario_db.get("nombre", "Empleado")
        
    if rol == "Encargado":
        return {
            "status": "skipped",
            "message": f"El usuario {nombre} es Encargado. No realiza ventas directas.",
            "rol": rol,
            "total_acumulado": 0.0
        }
        
    filtro_tickets = {
        "$or": [
            {"vendedor_correo": correo},
            {"correo_vendedor": correo},
            {"vendedor": correo}
        ],
        "procesado_en_corte": False, 
        "tipo": "VENTA"              
    }
    tickets_pendientes = list(tickets_col.find(filtro_tickets))
    total_efectivo = 0.0
    ids_tickets_a_cerrar = []
    
    for ticket in tickets_pendientes:
        try:
            total_efectivo += float(ticket.get("total", 0.0))
            ids_tickets_a_cerrar.append(ticket["_id"])
        except (ValueError, TypeError):
            pass
            
    corte_data = {
        "usuario_nombre": nombre,
        "usuario_correo": correo,
        "usuario_rol": rol,
        "monto_efectivo_declarado": total_efectivo,
        "total_calculado": total_efectivo,
        "observaciones": "Corte automático generado al cerrar sesión",
        "fecha_corte": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }
    cortes_caja_col.insert_one(corte_data)
    
    if ids_tickets_a_cerrar:
        tickets_col.update_many(
            {"_id": {"$in": ids_tickets_a_cerrar}},
            {"$set": {"procesado_en_corte": True}}
        )
    
    return {
        "status": "success",
        "message": f"Corte de caja registrado para {nombre}.",
        "rol": rol,
        "total_acumulado": total_efectivo
    }

# HISTORIAL DE CORTES PARA EL ADMIN / ENCARGADO
@app.get("/caja/cortes", tags=["Corte de Caja"])
def listar_cortes_caja():
    """Muestra la lista de cortes guardados"""
    cursor = cortes_caja_col.find()
    cortes = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        cortes.append(doc)
    return cortes

# -------------------------------------------------------------
# REGISTRAR CONSUMO PROPIO
# -------------------------------------------------------------
@app.post("/consumo-propio", tags=["Productos"])
def registrar_consumo_propio(req: dict):
    producto_id = req.get("codigo_barras") or req.get("producto_id")
    cantidad = int(req.get("cantidad", 1))
    correo_usuario = req.get("correo_usuario") or req.get("correo") or "carlos.mendoza@tiendita.com"
    motivo = req.get("motivo", "Consumo Empleado")
    
    producto = productos_col.find_one({"_id": producto_id})
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    
    inventario_actual = producto.get("inventario", 0)
    if inventario_actual < cantidad:
        raise HTTPException(status_code=400, detail=f"Stock insuficiente ({inventario_actual} disp).")
    
    productos_col.update_one({"_id": producto_id}, {"$inc": {"inventario": -cantidad}})
    
    precio_unitario = float(producto.get("precio_venta", 0.0))
    fecha_actual = datetime.utcnow()
    
    registro_consumo = {
        "producto_id": producto_id,
        "nombre_producto": producto.get("nombre", ""),
        "cantidad": cantidad,
        "precio_unitario": precio_unitario,
        "total": 0.0,
        "costo_real": precio_unitario * cantidad,
        "vendedor_correo": correo_usuario,
        "tipo": "CONSUMO_PROPIO",
        "procesado_en_corte": True,         
        "motivo": motivo,
        "fecha": fecha_actual.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    tickets_col.insert_one(registro_consumo)
    
    return {
        "status": "success",
        "message": f"Consumo registrado ({cantidad}x {producto.get('nombre')})",
        "inventario_nuevo": inventario_actual - cantidad
    }

# 7. MÓDULO DE PRODUCTOS
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
    productos = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])  # Fuerza _id a String para evitar fallos de parseo en Android
        if "proveedor" in doc and isinstance(doc["proveedor"], dict):
            doc["proveedor"] = doc["proveedor"].get("nombre", "General")
        productos.append(doc)
    return productos

@app.get("/productos/{producto_id}", tags=["Productos"], response_model=ProductoSchema)
def obtener_producto_por_id(producto_id: str):
    producto = productos_col.find_one({"_id": producto_id, "activo": True})
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    producto["_id"] = str(producto["_id"])
    if "proveedor" in producto and isinstance(producto["proveedor"], dict):
        producto["proveedor"] = producto["proveedor"].get("nombre", "General")
    return producto

@app.put("/productos/{producto_id}", tags=["Productos"])
def actualizar_producto(producto_id: str, datos_actualizados: ProductoSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    producto_existente = productos_col.find_one({"_id": producto_id})
    if not producto_existente:
        raise HTTPException(status_code=404, detail="El producto no existe en la tiendita.")
    
    precio_compra_viejo = float(producto_existente.get("precio_compra", 0.0))
    precio_venta_viejo = float(producto_existente.get("precio_venta", 0.0))
    
    cambio_compra = precio_compra_viejo != datos_actualizados.precio_compra
    cambio_venta = precio_venta_viejo != datos_actualizados.precio_venta
    
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
    
    datos_dict = datos_actualizados.dict(by_alias=True, exclude={"id"})
    
    datos_dict["fecha_creacion"] = producto_existente.get("fecha_creacion", datetime.utcnow().strftime("%Y-%m-%d"))
    datos_dict["fecha_actualizacion"] = datetime.utcnow().strftime("%Y-%m-%d")
    datos_dict["creado_por"] = producto_existente.get("creado_por", "AppAndroid")
    
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

@app.delete("/productos/{producto_id}", tags=["Productos"])
def eliminar_producto(producto_id: str, token_data: dict = Depends(verificar_permiso_encargado)):
    resultado = productos_col.update_one({"_id": producto_id}, {"$set": {"activo": False}})
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    return {"status": "success", "message": "Producto dado de baja exitosamente."}

# 8. MÓDULO DE CATEGORÍAS (PROTEGIDO)
@app.post("/categorias", tags=["Categorías"], status_code=status.HTTP_201_CREATED)
def crear_categoria(categoria: CategoriaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(categoria.nombre)
    existe = categorias_col.find_one({"nombre": {"$regex": regex, "$options": "i"}})
    if existe:
        raise HTTPException(
            status_code=400, 
            detail=f"La categoría '{categoria.nombre}' ya existe o es muy similar a '{existe['nombre']}'."
        )
    
    nueva_cat = categoria.dict(exclude={"id"})
    categorias_col.insert_one(nueva_cat)
    return {"status": "success", "message": f"Categoría '{categoria.nombre}' registrada correctamente."}

@app.get("/categorias", tags=["Categorías"])
def listar_categorias():
    cursor = categorias_col.find()
    return [{"_id": str(doc["_id"]), "nombre": doc["nombre"], "descripcion": doc.get("descripcion", "")} for doc in cursor]

@app.put("/categorias/{nombre}", tags=["Categorías"])
def actualizar_categoria(nombre: str, categoria: CategoriaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(nombre)
    resultado = categorias_col.update_one({"nombre": {"$regex": regex, "$options": "i"}}, {"$set": categoria.dict(exclude={"id"})})
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="La categoría no existe.")
    
    if nombre != categoria.nombre:
        productos_col.update_many(
            {"categoria_nombre": {"$regex": regex, "$options": "i"}},
            {"$set": {"categoria_nombre": categoria.nombre}}
        )
        
    return {"status": "success", "message": f"Categoría '{nombre}' actualizada correctamente."}

@app.delete("/categorias/{nombre}", tags=["Categorías"])
def eliminar_categoria(nombre: str, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(nombre)
    
    producto_asociado = productos_col.find_one({
        "categoria_nombre": {"$regex": regex, "$options": "i"},
        "activo": True
    })
    
    if producto_asociado:
        raise HTTPException(
            status_code=400, 
            detail=f"No se puede eliminar la categoría '{nombre}' porque tiene productos activos asociados (ej. '{producto_asociado['nombre']}')."
        )
    resultado = categorias_col.delete_one({"nombre": {"$regex": regex, "$options": "i"}})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="La categoría no existe.")
        
    return {"status": "success", "message": f"Categoría '{nombre}' eliminada correctamente."}

# 9. MÓDULO DE PROVEEDORES Y DISTRIBUIDORES (NUEVAS COLECCIONES)
@app.get("/proveedores", tags=["Proveedores"])
def listar_proveedores():
    cursor = proveedores_col.find()
    return [{"_id": str(doc["_id"]), "nombre": doc["nombre"]} for doc in cursor]

@app.post("/proveedores", tags=["Proveedores"], status_code=status.HTTP_201_CREATED)
def crear_proveedor_coleccion(prov: ProveedorColeccionSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    existe = proveedores_col.find_one({"nombre": prov.nombre})
    if existe:
        raise HTTPException(status_code=400, detail=f"El proveedor '{prov.nombre}' ya existe.")
    proveedores_col.insert_one(prov.dict())
    return {"status": "success", "message": f"Proveedor '{prov.nombre}' registrado correctamente."}

@app.get("/distribuidores", tags=["Distribuidores"])
def listar_distribuidores():
    cursor = distribuidores_col.find()
    return [{"_id": str(doc["_id"]), "nombre": doc["nombre"]} for doc in cursor]

@app.post("/distribuidores", tags=["Distribuidores"], status_code=status.HTTP_201_CREATED)
def crear_distribuidor(dist: DistribuidorSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    existe = distribuidores_col.find_one({"nombre": dist.nombre})
    if existe:
        raise HTTPException(status_code=400, detail=f"El distribuidor '{dist.nombre}' ya existe.")
    distribuidores_col.insert_one(dist.dict())
    return {"status": "success", "message": f"Distribuidor '{dist.nombre}' registrado correctamente."}

# 10. MÓDULO DE MARCAS (PROTEGIDO Y ACTUALIZADO)
@app.post("/marcas", tags=["Marcas"], status_code=status.HTTP_201_CREATED)
def crear_marca(marca: MarcaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(marca.nombre)
    existe = marcas_col.find_one({"nombre": {"$regex": regex, "$options": "i"}})
    if existe:
        raise HTTPException(
            status_code=400, 
            detail=f"La marca '{marca.nombre}' ya existe o es muy similar a '{existe['nombre']}'."
        )
    
    nueva_marca = marca.dict(exclude={"id"})
    marcas_col.insert_one(nueva_marca)
    return {"status": "success", "message": f"Marca '{marca.nombre}' registrada correctamente."}

@app.get("/marcas", tags=["Marcas"])
def listar_marcas():
    cursor = marcas_col.find()
    return [
        {
            "_id": str(doc["_id"]),
            "nombre": doc["nombre"],
            "origen": doc.get("origen", ""),
            "distribuidor": doc.get("distribuidor", ""),
            "proveedor": doc.get("proveedor", "")
        }
        for doc in cursor
    ]

@app.put("/marcas/{nombre}", tags=["Marcas"])
def actualizar_marca(nombre: str, marca: MarcaSchema, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(nombre)
    resultado = marcas_col.update_one({"nombre": {"$regex": regex, "$options": "i"}}, {"$set": marca.dict(exclude={"id"})})
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="La marca no existe.")
    
    if nombre != marca.nombre:
        productos_col.update_many(
            {"marca_nombre": {"$regex": regex, "$options": "i"}},
            {"$set": {"marca_nombre": marca.nombre}}
        )
    return {"status": "success", "message": f"Marca '{nombre}' actualizada correctamente."}

@app.delete("/marcas/{nombre}", tags=["Marcas"])
def eliminar_marca(nombre: str, token_data: dict = Depends(verificar_permiso_encargado)):
    regex = crear_regex_insensible(nombre)
    
    producto_asociado = productos_col.find_one({
        "marca_nombre": {"$regex": regex, "$options": "i"},
        "activo": True
    })
    
    if producto_asociado:
        raise HTTPException(
            status_code=400, 
            detail=f"No se puede eliminar la marca '{nombre}' porque tiene productos activos asociados (ej. '{producto_asociado['nombre']}')."
        )
    resultado = marcas_col.delete_one({"nombre": {"$regex": regex, "$options": "i"}})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="La marca no existe.")
        
    return {"status": "success", "message": f"Marca '{nombre}' eliminada correctamente."}