@echo off

del /F /S /Q screen.png

cd gameStart
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete gameStart success
) else ( 
	echo cd gameStart failed
)
cd welcome
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete welcome success
) else ( 
	echo 'cd welcome failed'
)
cd dailyLanding
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete dailyLanding success
) else ( 
	echo 'cd deailLanding failed'
)

cd checkPoints
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete checkPoints success
) else ( 
	echo 'cd checkPoints failed'
)

cd pointEnter
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete pointEnter success
) else ( 
	echo 'cd pointEnter failed'
)

cd adventure
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete adventure success
) else ( 
	echo 'cd adventure failed'
)

cd endCnt
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete endCnt success
) else ( 
	echo 'cd endCnt failed'
)

cd endTime
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete endTime success
) else ( 
	echo 'cd endTime failed'
)

cd endStep
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete endStep success
) else ( 
	echo 'cd endStep failed'
)

cd pointSuccess
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete pointSuccess success
) else ( 
	echo 'cd pointSuccess failed'
)

cd pointFail
if %errorlevel% == 0 ( 
	del /F /S /Q  *.*
	cd ..
	echo delete pointFail success
) else ( 
	echo 'cd pointFail failed'
)