import pickle
def fraud_classes_mapping(column):
    '''
    Function for mapping 24+14 categories of attacks into 5 (incl. normal) main classes
    -----------------
    column: pd.Series
    '''
    with open('utils/classes_mapping.pickle', 'rb') as f:
        classes_mapping = pickle.load(f)
    
    classes_mapping = {i.split(' ')[0]:i.split(' ')[1] for i in classes_mapping.split('\n')}
    classes_mapping['normal'] = 'norm'
    
    return column.map(classes_mapping)