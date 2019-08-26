<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;


class TokensController extends Controller
{
    public function login(Request $request){
        $credenciales = $request->only('email','password');

        $validador = Validator::make($credenciales,[
            'email'    =>'required|email',
            'password' =>'required'
        ]);

        if ($validador->fails()){
            return response()->json([
                   'sucess' =>false,
                   'mensaje'=>'validacion incorrecta',
                   'errors' =>$validador->errors()
            ],422);
        }
        /*generamos el token con las credenciales del email y password */
        $token = JWTAuth::attempt($credenciales);

        if ($token){
            return response()->json([
                'sucess' =>true,
                'token' =>$token,
                'user'=>User::where('email',$credenciales['email'])->get()->first()
         ],200);
        }else{
            return response()->json([
                'sucess' =>false,
                'mensaje'=>'credenciales incorrectas',
                'errors' =>$validador->errors()
         ],401);
        }

        return null;
    }

    public function refreshToken(){
        /*obtenemos el token  */
        $token =  JWTAuth::getToken();
        try {
            $token = JWTAuth::refresh($token);
            return response()->json([
                'sucess' =>true,
                'token' =>$token
                ],401);

        } catch (TokenExpiredException  $ex) {
            return response()->json([
                'sucess' =>false,
                'mensaje'=>'token expiro'
                ],422);
            }catch (TokenBlacklistedException  $ex) {
                return response()->json([
                    'sucess' =>false,
                    'mensaje'=>'No se puede refresh el token'
                    ],422);

        }
    }

    public function logout(){
        $token =  JWTAuth::getToken();
        try {
            JWTAuth::invalidate($token);

            return response()->json([
                'sucess' =>true,
                'mensaje'=>'se expiro correctamente el token'
                ],200);
        } catch (JWTException $ex) {
            return response()->json([
                'sucess' =>false,
                'mensaje'=>'fallo logout'
                ],422);
        }
    }
}
