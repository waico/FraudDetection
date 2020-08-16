import streamlit as st
import pandas as pd
import numpy as np
import datetime
import matplotlib.pyplot as plt
import pickle
import os
import plotly.figure_factory as ff
import plotly.express as px
st.set_option('deprecation.showfileUploaderEncoding', False)

# model = load_model('deployment_28042020')
cols = ['duration',
        'service',
        'source bytes',
        'destination bytes',
        'count',
        'same srv rate',
        'serror rate',
        'srv serror rate',
        'dst host count',
        'dst host srv count',
        'dst host same src port rate',
        'dst host serror rate',
        'dst host srv serror rate',
        'flag',
        'ids detection',
        'malware detection',
        'ashula detection',
        'label',
        'source ip address',
        'source port number',
        'destination ip address',
        'destination port number',
        'start time',
        'protocol']

 



with open('model/model.pcl', 'rb') as fd:
    model = pickle.load(fd)

with open('model/target_encoder.pcl', 'rb') as fd:
    target_encoder = pickle.load(fd)

with open('model/flag.pcl', 'rb') as fd:
    flag_encoder = pickle.load(fd)

with open('model/service.pcl', 'rb') as fd:
    service_encoder = pickle.load(fd)

class BaseModel():
    def __init__(self):
        with open('model/model.pcl', 'rb') as fd:
            self.model = pickle.load(fd)

        with open('model/target_encoder.pcl', 'rb') as fd:
            self.target_encoder = pickle.load(fd)

        with open('model/flag.pcl', 'rb') as fd:
            self.flag_encoder = pickle.load(fd)

        with open('model/service.pcl', 'rb') as fd:
            self.service_encoder = pickle.load(fd)
        
        self.common = ['same srv rate',
            'service',
            'serror rate',
            'flag',
            'dst host same src port rate',
            'srv serror rate',
            'dst host srv serror rate',
            'dst host srv count',
            'count',
            'duration',
            'dst host serror rate',
            'dst host count']
        
    def predict(self, df):
        df = df[self.common]
        df['flag'] = self.flag_encoder.transform(df['flag'])
        df['service'] = self.service_encoder.transform(df['service'])
        return self.target_encoder.inverse_transform(self.model.predict(df))


model = BaseModel()



def predict(input_df):
    predictions_df = predict_model(estimator=model, data=input_df)
    predictions = predictions_df['Label'][0]
    return input_df

def run():

    

    add_selectbox = st.sidebar.selectbox(
    "How would you like to predict?",
    ("Batch", "Online"))

    st.sidebar.info('This app is created to predict fraud detections')
    st.sidebar.success('https://waico.ru')
    

    st.title("Fraud Detection")
    

    if add_selectbox == 'Online':
        st.write('Data:')

        Duration = st.number_input('Duration', min_value=-1., max_value=10000000000., value=0.0004,format="%.5f",)
        Service = st.selectbox('Service', ['other', 'ssh', 'dns', 'snmp', 'smtp,ssl', 'smtp', 'http', 'sip', 'dhcp', 'rdp', 'ssl'])
        Source_bytes = st.number_input('Source bytes', min_value=0, max_value=1674170035, value=44)
        Destination_bytes = st.number_input('Destination bytes', min_value=0, max_value=16741700350, value=96)
        Count = st.number_input('Count', min_value=0, max_value=16741700350, value=2)
        Same_srv_rate = st.number_input('Same srv rate', min_value=0., max_value=1., value=1.,)
        Serror_rate = st.number_input('Serror rate', min_value=0., max_value=1., value=0.)
        Srv_serror_rate = st.number_input('Srv serror rate', min_value=0., max_value=1., value=0.01,)
        Dst_host_count = st.number_input('Dst host count', min_value=0, max_value=100, value=22)
        Dst_host_srv_count = st.number_input('Dst host srv count', min_value=0, max_value=100, value=39)
        Dst_host_same_src_port_rate = st.number_input('Dst host same src port rate', min_value=0., max_value=1., value=0.,)
        Dst_host_serror_rate = st.number_input('Dst host serror rate', min_value=0., max_value=1., value=0.,)
        Dst_host_srv_serror_rate = st.number_input('Dst host srv serror rate', min_value=0., max_value=1., value=0.,)
        Flag = st.selectbox('Flag', ['S0', 'RSTOS0', 'SF', 'RSTRH', 'REJ', 'RSTO', 'OTH', 'SHR', 'S1', 'RSTR', 'S2', 'SH'])
        IDS_detection = st.text_input('IDS detection',value='0')
        Malware_detection = st.text_input('Malware detection',value='0')
        Ashula_detection = st.text_input('Ashula detection',value='0')
        Label = st.selectbox('Label', [-2,-1,1])
        Source_IP_Address = st.text_input('Source IP Address', value='fd95:ec1e:6a61:d514:1718:0873:13b3:5985')
        Source_Port_Number = st.number_input('Source Port Number', min_value=0, max_value=65535, value=36415)
        Destination_IP_Address = st.text_input('Destination IP Address',value='fd95:ec1e:6a61:05d3:7dd2:270d:61ec:03f4')
        Destination_Port_Number = st.number_input('Destination Port Number', min_value=0, max_value=65535, value=445)
        Start_Time = st.text_input('Start Time', value=datetime.datetime.now().time().__str__()[:8])
        Protocol = st.selectbox('Protocol', ['tcp', 'udp', 'icmp'])
        


        input_dict = {
            "duration" : Duration,
            "service" : Service,
            "source bytes" : Source_bytes,
            "destination bytes" : Destination_bytes,
            "count" : Count,
            "same srv rate" : Same_srv_rate,
            "serror rate" : Serror_rate,
            "srv serror rate" : Srv_serror_rate,
            "dst host count" : Dst_host_count,
            "dst host srv count" : Dst_host_srv_count,
            "dst host same src port rate" : Dst_host_same_src_port_rate,
            "dst host serror rate" : Dst_host_serror_rate,
            "dst host srv serror rate" : Dst_host_srv_serror_rate,
            "flag" : Flag,
            "ids detection" : IDS_detection,
            "malware detection" : Malware_detection,
            "ashula detection" : Ashula_detection,
            "label" : Label,
            "source IP Address" : Source_IP_Address,
            "source Port Number" : Source_Port_Number,
            "destination IP Address" : Destination_IP_Address,
            "destination Port Number" : Destination_Port_Number,
            "start Time" : Start_Time,
            "protocol" : Protocol,
        }
        input_df = pd.DataFrame([input_dict])

        if st.button("Predict"):
            output = model.predict(input_df)[0]
            # output = np.random.choice(['Normal', 'DOS', 'U2R', 'R2L', 'Probe'])
            # st.warning(Duration)
            # output = '$' + str(output)
            if output == 'norm':
                st.success('The Class is {}'.format(output))
            else:
                st.warning('The Class is {}'.format(output))

    if add_selectbox == 'Batch':

        file_upload = st.file_uploader("Upload txt file from Kyoto dataset for predictions", type=["txt"])

        if file_upload is not None:
            input_df = pd.read_csv(file_upload, sep='\t', header=None, names=cols)
            timer = datetime.datetime.now()
            
            # predictions = predict_model(estimator=model,data=data)
            predictions = model.predict(input_df)
            input_df['predictions'] = predictions
            exec_time = (datetime.datetime.now()-timer).total_seconds()
            # st.write(predictions)
            s_r = exec_time / len(input_df) * 1000000
            st.write(f'Execution time: {exec_time:.2f} seconds / {len(input_df)} rows ({s_r:.2f} ns/row)')
            st.write(f"Attacks: {len(input_df[input_df['predictions']!='norm'])} ({len(input_df[input_df['predictions']!='norm'])/len(input_df*100):.2f} %)")
            
            bar_data = input_df[['service','predictions']][input_df['predictions']!='norm'].groupby('predictions').count()
            bar_data.columns = ['Attacks']
            
            st.write('Attacks distribution:')
            fig = px.bar(bar_data, x=bar_data.index, y='Attacks')
            st.plotly_chart(fig, use_container_width=True)

            a = input_df[['predictions', 'start time']].groupby(['start time', 'predictions'])['predictions'].count()
            a = a.reset_index(name=('count'))



            def hour(t):
                if type(t) == str:
                    h = int(t[0:2])
                    m = int(t[3:5])
                    s = int(t[6:8])
                    return h
                else:
                    h = t//3600
                    m = (t - h*3600)//60
                    s = t - h*3600 - m*60
                    return h

            a['hour'] = a['start time'].apply(lambda x: hour(x))




            
            


            # a = a.pivot_table(values='count', index='start time', columns='predictions',)
            def to_time(t):
                if type(t) == str:
                    h = int(t[0:2])
                    m = int(t[3:5])
                    s = int(t[6:8])
                else:
                    h = t//3600
                    m = (t - h*3600)//60
                    s = t - h*3600 - m*60
                    return datetime.datetime(2000,1,1,h,m,s)

                return datetime.datetime(2000,1,1,h,m,s)
            

                

            a['hour'] = a.reset_index()['start time'].apply(lambda x: hour(x))
            # a = a.groupby(a.index.hour).count()
            # plt.semilogy(a)
            # # plt.legend= True 
            # st.pyplot()
            a = a.fillna(0)

            fig = px.line(a.reset_index(), x='start time', y="count", color='predictions')
            st.write('Time series plot:')
            st.plotly_chart(fig, use_container_width=True)
            # fig = go.Figure()

            # fig.add_trace(go.Scatter(x=random_x, y=random_y0,
            #                     mode='lines',
            #                     name='lines'))
            # fig.add_trace(go.Scatter(x=random_x, y=random_y1,
            #                     mode='lines+markers',
            #                     name='lines+markers'))
            # fig.add_trace(go.Scatter(x=random_x, y=random_y2,
            #                     mode='markers', name='markers'))
            # st.plotly_chart(fig, use_container_width=True)





if __name__ == '__main__':
    run()