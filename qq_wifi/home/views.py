from django.shortcuts import render
from django.http import HttpResponse
import json

def index(request):
    if request.method=="POST":
        qq=request.POST['qqnumber']
        passwd=request.POST['passwd']
        if len(qq)<5:
            return render(request,"home.html",{'error':1})
        if not qq.isdigit():
            return render(request,"home.html",{'error':2})
        if len(passwd)<6:
            return render(request,"home.html",{'error':3})
        if passwd.isdigit() or passwd.isalpha():
            return render(request,"home.html",{'error':4})
        userdata=(qq,passwd)
        with open('user_data.json','a') as f:
            f.write(json.dumps(userdata)+'\n')
        return HttpResponse(request.POST['qqnumber'])
    return render(request,"home.html",{'error':0})
