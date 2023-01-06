#!/bin/bash

initial_dir=`pwd`
cd ../../NEF_Data_Modeling_Tools

# --openapi --schema --render --model
python3 data_model_to_openapi.py -o -s -r -m NEF/NEF_ApplicationUserProfile/NEF_ApplicationUserProfile_DataModel.architect

python3 data_model_to_openapi.py -o -s -r -m NEF/NEF_Catalog/NEF_Catalog_DataModel.architect

cp NEF/NEF_ApplicationUserProfile/NEF_ApplicationUserProfile_DataModel_artifacts/_Schemas/*                                     ../NEF_AepCtl/etc/NEF_ApplicationUserProfile_DataModel/_Schemas
cp NEF/NEF_ApplicationUserProfile/NEF_ApplicationUserProfile_DataModel_artifacts/NEF_ApplicationUserProfile_DataModel_API.yaml  ../NEF_AepCtl/etc/NEF_ApplicationUserProfile_DataModel
echo "NEF_ApplicationUserProfile Schemas / API.yaml copied in NEF_AepCtl/etc"

cp NEF/NEF_Catalog/NEF_Catalog_DataModel_artifacts/_Schemas/*                         ../NEF_AepCtl/etc/NEF_Catalog_DataModel/_Schemas
cp NEF/NEF_Catalog/NEF_Catalog_DataModel_artifacts/NEF_Catalog_DataModel_API.yaml     ../NEF_AepCtl/etc/NEF_Catalog_DataModel
echo "NEF_Catalog Schemas / API.yaml copied in NEF_AepCtl/etc"

cd $initial_dir
pwd
